/****************************************************
 NAME: Sam Schaefer
 CS410
 FILE: Extract msg from img.ppm file then decrpyt it
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


unsigned char * aes_gcm_decrypt(unsigned char * text, long size, unsigned char * inText, unsigned char * out)
{
    EVP_CIPHER_CTX *ctx;
    int outlen, tmplen, rv;
    
    ctx = EVP_CIPHER_CTX_new();
    
    /* Select cipher */
    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    
    /* Set IV length, omit for 96 bits */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(gcm_iv), NULL);
    
    /* Specify key and IV */
    EVP_DecryptInit_ex(ctx, NULL, NULL, out, gcm_iv);
    
    /* Decrypt plaintext */
    EVP_DecryptUpdate(ctx, out, &outlen, text, strlen(text));
    
    /* Set expected tag value. */
    //EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(gcm_tag), gcm_tag);
    
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

int main(int argc, char **argv){
    
    FILE *stego, *msg;
    
    msg = fopen("delete.txt", "w");
    
    char c;
    unsigned char *msgOne;
    
    stego = fopen(argv[2], "r");
    
    int size = 0;
    fseek(stego,0,SEEK_END);
    size = ftell(stego);
    fseek(stego, 0, SEEK_SET);
    
	//Comsume the first few junk lines of the file
    char cc[100];
    for(int q=0; q<3; q++)
    {
        fgets(cc, sizeof(cc), stego);
    }
    
    int buff[size];
    int peel, mask;
    int dirty;
    int count = 0;
    for(int u = 0; u < 1000; u++)
    {
        fscanf(stego, "%d", &dirty);
        buff[count] = dirty;
        count++;
    }
    
    int eight = 0;
    int binChar[7];
    unsigned char *binCh;
    
    //take LSB by masking then converting from dec to unsigned char
    for(int i =0; i<1000; i++)
    {
        peel = buff[i];
        peel = (peel << 7) & 0x80;
        
        if(peel == 128)
        {
            peel = 1;
        }
        //load binChar with 8 bits then convert it to a char
        binChar[eight] = peel;
        eight++;
        
        if(eight == 8)
        {
            //	printf("-\n");
            eight = 0;
            unsigned char test = binChar[0] << 7 |
            binChar[1] << 6 |
            binChar[2] << 5 |
            binChar[3] << 4 |			
            binChar[4] << 3 |
            binChar[5] << 2 |
            binChar[6] << 1 |
            binChar[7] << 0;
            //printf("my char: %c\n", test); 
            
            fprintf(msg,"%c", test);		
        }		
    }
    
    fclose(msg);
    
    int SHA1_LEN = 32;
    unsigned char * out = (unsigned char *) malloc(sizeof(unsigned char) * SHA1_LEN);
    
    FILE *file = fopen("delete.txt", "r" );
    fseek(file, 0, SEEK_END);
    long size2 = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    unsigned char * text = (unsigned char *) malloc (sizeof(unsigned char)*size2 + 1);
    memset(text, '\0', sizeof(unsigned char)*size2 + 1);
    fread(text, 1, size2, file);
    
    int PKCatch;
    int passlen = strlen(argv[6]);
    
    PKCS5_PBKDF2_HMAC_SHA1(argv[6], strlen(argv[6]), NULL, 0, 10000, SHA1_LEN, out);
    
    unsigned char * afterCipher = aes_gcm_decrypt(text, size2, afterCipher, out);
    fclose(file);
    
    int i = 0;
    file = fopen(argv[4], "w+");
    i = fwrite(afterCipher,sizeof(unsigned char), size2, file);
    fclose(file);
    
    return 0;
}		
