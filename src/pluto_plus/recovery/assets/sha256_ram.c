/* PPU RAM-only SHA-256 helper. No peripheral, flash, environment or filesystem IO.
 * ARM entry ABI: go 06000000 INPUT_ADDRESS LENGTH
 * SHA-256 output: 32 bytes at 06010000. Only bounded DDR reads are permitted.
 */
typedef unsigned int u32;
typedef unsigned char u8;
static const u32 k[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
static u32 r(u32 v, unsigned n) { return (v >> n) | (v << (32-n)); }
static void block(u32 h[8], const u8 p[64]) {
 u32 w[64],a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],v=h[7];
 unsigned i;
 for(i=0;i<16;i++) w[i]=((u32)p[i*4]<<24)|((u32)p[i*4+1]<<16)|((u32)p[i*4+2]<<8)|p[i*4+3];
 for(i=16;i<64;i++) w[i]=w[i-16]+(r(w[i-15],7)^r(w[i-15],18)^(w[i-15]>>3))+w[i-7]+(r(w[i-2],17)^r(w[i-2],19)^(w[i-2]>>10));
 for(i=0;i<64;i++) {
  u32 t=v+(r(e,6)^r(e,11)^r(e,25))+((e&f)^((~e)&g))+k[i]+w[i];
  u32 q=(r(a,2)^r(a,13)^r(a,22))+((a&b)^(a&c)^(b&c));
  v=g;g=f;f=e;e=d+t;d=c;c=b;b=a;a=t+q;
 }
 h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=v;
}
void ppu_sha256(const u8 *data,u32 size,u8 out[32]) {
 u32 h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
 u8 tail[128];u32 offset=0,remaining;unsigned i,n;
 while(size-offset>=64) {block(h,data+offset);offset+=64;}
 remaining=size-offset;
 for(i=0;i<128;i++) tail[i]=0;
 for(i=0;i<remaining;i++) tail[i]=data[offset+i];
 tail[remaining]=0x80;n=remaining<56?64:128;
 /* Entry permits <=32MiB, so bit length fits in 32 bits. */
 for(i=0;i<4;i++) tail[n-1-i]=(u8)((size*8)>>(i*8));
 block(h,tail);if(n==128) block(h,tail+64);
 for(i=0;i<32;i++) out[i]=(u8)(h[i/4]>>(24-(i%4)*8));
}
static int number(const char *s,u32 *out) {
 unsigned n=0;u32 v=0;
 for(;*s;s++) {
  u32 d;if(++n>8)return 0;
  if(*s>='0'&&*s<='9')d=*s-'0';else if(*s>='a'&&*s<='f')d=*s-'a'+10;else return 0;
  v=(v<<4)|d;
 }
 *out=v;return n!=0;
}
#ifndef PPU_HOST_TEST
__attribute__((section(".text.entry"))) int entry(int argc,char *const argv[]) {
 u32 address,size;
 if(argc!=3||!number(argv[1],&address)||!number(argv[2],&size))return 1;
 if(address<0x08000000||address>=0x20000000||size>0x02000000||size>0x20000000-address)return 2;
 ppu_sha256((const u8 *)address,size,(u8 *)0x06010000);
 return 0;
}
#endif
