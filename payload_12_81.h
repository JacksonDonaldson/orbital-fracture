typedef int func(char*, ...);
typedef int perm(char*, int, char*, int, char*, int);
typedef void send(int, char*, int, int);
typedef void empty(void);
typedef void cpy(char*, char*, unsigned int);
typedef void single(int);
typedef void dbl(int, int);

typedef void tb_com(unsigned char, unsigned char);
typedef void quad(int, int, int, int);


func* debug_printf = (func*) 0x200196b0;
single* save_sha = (single*) 0x20018b98;
empty* ret = (empty*) 0x20044504;
send* send_http_response = (send*) 0x2003bcb0;
tb_com* send_to_tb = (tb_com*) 0x20018ffc;
single* ring_chime = (single*) 0x20005c6c;
quad* acb_configure = (quad*) 0x200050fc;
empty* raise_acb = (empty*) 0x20005850;
single* sleep = (single*) 0x200195fc;
single* spi_erase = (single*) 0x200171cc;
cpy* spi_write = (cpy*) 0x20017258;


