/****************************************************
    NAME: Sam Schaefer
    CS410
    FILE: Encrypt a message then embed it into a IMG.ppm (flipping LSB's)
 
 ***************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>


static const unsigned char gcm_iv[] = {
    0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
};

static const unsigned char gcm_tag[] = {
    0x67, 0xba, 0x05, 0x10, 0x26, 0x2a, 0xe4, 0x87, 0xd7, 0x37, 0xee, 0x62,
    0x98, 0xf7, 0x7e, 0x0c
};


unsigned char* aes_gcm_encrypt(char * plain, long size, unsigned char * CT, unsigned char * out)
{
    
    EVP_CIPHER_CTX *ctx;
    int outlen, tmplen;
    unsigned char * outbuf[1024];
    
    ctx = EVP_CIPHER_CTX_new();
    
    /* Set cipher type and mode */
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    
    ///* Set IV length if default 96 bits is not appropriate */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(gcm_iv), NULL);
    
    /* Initialise key and IV */
    EVP_EncryptInit_ex(ctx, NULL, NULL, out, gcm_iv);
    
    /* Encrypt plaintext */
    EVP_EncryptUpdate(ctx, out, &outlen, plain, strlen(plain));
    
    ///* Get tag */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, outbuf);
    
    EVP_CIPHER_CTX_free(ctx);
    return CT = out;
}


int main(int argc,char ** argv)
{
    int SHA1_LEN = 32;
    unsigned char* out = (unsigned char *) malloc(sizeof(unsigned char) * SHA1_LEN);
	    
    FILE *file = fopen(argv[4], "r" );
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    FILE *cText;
    
    unsigned char * text = (unsigned char *) malloc (sizeof(unsigned char)*size + 1);
    memset(text, '\0', sizeof(unsigned char)*size + 1);
    fread(text, 1, size, file);
    
    int PKCatch;
    int  passlen = strlen(argv[8]);
    
    PKCS5_PBKDF2_HMAC_SHA1(argv[8], strlen(argv[8]), NULL, 0, 10000, SHA1_LEN, out);
    
    
    unsigned char * cipheredtext = NULL;
    cipheredtext = aes_gcm_encrypt(text, size, cipheredtext, out);
    
    fclose(file);
    file = fopen(argv[4], "r");
    int inOut = 0;
    char nextChar = getc(file);
    
    fclose(file);
    cText = fopen("cipher.txt", "w");
    
    inOut = fwrite(cipheredtext, sizeof(unsigned char), size, cText);
    
    //fclose(cText);

    int messageLen;
    int i = 0;
    int sizeText = 0;
    FILE *cover, *target, *textIn;
    textIn = fopen("cipher.txt", "r");
   
    int sizeTest = 0; 
    fseek(cText, 0, SEEK_END);
    sizeTest = ftell(cText);
    fseek(cText, 0, SEEK_SET);
    
    fseek(textIn, 0, SEEK_END);
    sizeText = ftell(textIn);
    fseek(textIn, 0, SEEK_SET);
    
    unsigned char buff;
    fscanf(textIn, "%c", &buff);
    messageLen = sizeText;
    char c;
    
    cover = fopen(argv[2], "r");
    
    target = fopen(argv[6], "r+");
    
    //copy cover.ppm into target.ppm
    while( ( c = fgetc(cover) ) != EOF)
    {
        fputc(c, target);
    }	
    
    int size2 = 0;
    fseek(target,0,SEEK_END);
    size2 = ftell(target);
    fseek(target, 0, SEEK_SET);
    
    int dirty;
    int dirt[size2];
    
    //skip first few lines of target.ppm (P3 X and Y and RGB COLOR lines)
    char cc[100];
    for(int q=0; q<3; q++)
    {
        fgets(cc, sizeof(cc), target);
    }
    
    int k = 0;
    int j = 7;
    int update;
    int byte;
    int yy = 0;	
    int count2 = 0;
    
    //EMBED ON LSB
    
    for(int g=0;g<messageLen-1; g++)
    {
        //printf("buff: %c\n", buff);
        byte = buff;
        
        for(int d=7; -1 < d; d--)
        {
            update = byte;
    	    fscanf(target, "%d", &dirty);
           	//printf("first to get dirty: %d\n", dirty);
            
            update = update & (1<<d);
            
            if(update == 0)
            {
              //  printf("& dirty: %d ", dirty);
                dirty &= 0xFE;
                dirt[count2] = dirty;
                //printf("dirt: %d\n", dirt[count2]);
                //printf("dirty: %d\n", dirty);
            }
            else
            {
               // printf("| dirty: %d ", dirty);
                dirty |= 0x01;
                dirt[count2] = dirty;
              //  printf("dirty: %d\n", dirty);
            }
            
            count2++;
        }	
        
        fscanf(textIn, "%c", &buff);
    }
    
    //rewind target file and print new values into it creating your stego.ppm
    rewind(target);
				
    for(int q=0; q<3; q++)
    {
        fgets(cc, sizeof(cc), target);
    }
    
    for(int m = 0; m < count2; m++)
    {
        fprintf(target,"%d ", dirt[m]);
    }
    
    printf("\n %s created, message hidden~~~\n\n", argv[6]);
    
    return 0;

    
}
