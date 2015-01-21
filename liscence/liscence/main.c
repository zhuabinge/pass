#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#define ID_EN_FILE_PATH "/home/lele/Template/id_en_file"
#define USR_PRV_PATH "/home/lele/Template/usr_prv.key"
#define MFR_PRV_PATH "/home/lele/Template/mfr_prv.key"
#define LISCENCE_EN_PATH "/home/lele/Template/liscence_en_file"
#define SIZE 128

char *usr_prv_de(FILE *id_en_file, char *usr_prv_path) {

    char *id_en;
    id_en = (char *)malloc(SIZE);
    memset(id_en, '\0', SIZE);

    int ret = 0;
    if((ret = fread(id_en, 1, SIZE, id_en_file)) == 0) {

        perror("fread");
        return  NULL;
    }
    fclose(id_en_file);

    FILE *usr_prv_file;
    if((usr_prv_file = fopen(usr_prv_path, "r")) == NULL) {

        printf("open usr_prv.key failed\n");
        return NULL;
    }

    RSA *usr_prv;
    if((usr_prv = PEM_read_RSAPrivateKey(usr_prv_file, NULL, NULL, NULL)) == NULL) {

        ERR_print_errors_fp(stdout);
        return NULL;
    }

    char *id_de;
    id_de = (char *)malloc(RSA_size(usr_prv));
    memset(id_de, '\0', RSA_size(usr_prv));

    if(RSA_private_decrypt(RSA_size(usr_prv), (u_char *)id_en, (u_char *)id_de, usr_prv, RSA_NO_PADDING) < 0)
        return NULL;

    free(usr_prv);
    fclose(usr_prv_file);
    //printf("id_de is: %s\n", id_de);

    return id_de;
}

char *mfr_prv_en(char *liscence, char *mfr_prv_path) {

    FILE *mfr_prv_file;
    if((mfr_prv_file = fopen(mfr_prv_path, "r")) == NULL) {

        printf("open mfr_prv.key failed\n");
        return NULL;
    }

    RSA *mfr_prv;
    if((mfr_prv = PEM_read_RSAPrivateKey(mfr_prv_file, NULL, NULL, NULL)) == NULL) {

        ERR_print_errors_fp(stdout);
        return NULL;
    }

    char *liscence_en;
    liscence_en = (char *)malloc(RSA_size(mfr_prv));
    memset(liscence_en, '\0', RSA_size(mfr_prv));

    if(RSA_private_encrypt(RSA_size(mfr_prv), (u_char *)liscence, (u_char *)liscence_en, mfr_prv, RSA_NO_PADDING) < 0)
        return NULL;

    fclose(mfr_prv_file);
    //printf("liscence_en is %x \n",liscence_en);

    FILE *liscence_en_file;
    if((liscence_en_file = fopen(LISCENCE_EN_PATH, "w")) == NULL) {
        printf("creating liscence_en_file failed\n");
        return NULL;
    }

    fwrite(liscence_en, 1, RSA_size(mfr_prv), liscence_en_file);
    fclose(liscence_en_file);
    free(mfr_prv);


    return liscence_en;
}

int main(void) {

    char *id_de = NULL;

    FILE *id_en_file;
    id_en_file = fopen(ID_EN_FILE_PATH, "r");

    if(id_en_file == NULL) {

        printf("No id_en_file found: ");
        return -1;

    } else {

        id_de = usr_prv_de(id_en_file, USR_PRV_PATH);

        char *date;
        date = (char *)malloc(10);
        memset(date, '\0', 10);
        printf("set an authoried period (e.g. 20250101):\n");
        scanf("%s", date);
        printf("authoried date set to %s\n", date);

        char *liscence_temp;
        liscence_temp = (char *)malloc(strlen(date) + strlen(id_de) + 1);
        memset(liscence_temp, '\0', strlen(date) + strlen(id_de) + 1);

        char *liscence = liscence_temp;
        while(*date != '\0') *liscence_temp++ = *date++;
        while(*id_de != '\0') *liscence_temp++ = *id_de++;
        //printf("liscence is %s\n", liscence);

        mfr_prv_en(liscence, MFR_PRV_PATH);

    }

    return 0;
}

