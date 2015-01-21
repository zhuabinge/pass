#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#define LISCENCE_PATH "/home/light/liscence_en_file"
#define USR_PUB_PATH "/home/light/usr_pub.key"
#define MFR_PUB_PATH "/home/light/mfr_pub.key"
#define SIZE 128

char *get_cpu_id(void) {

    int ret = 0;
    FILE *cpu_id_str;
    if((cpu_id_str = popen("dmidecode -t 4","r")) == NULL) {

        printf("sys_sn achievement failed\n");
        return NULL;
    }

    char *cpu_id_flag = "ID:A";
    char *cpu_id_temp;
    cpu_id_temp = (char *)malloc(256);
    memset(cpu_id_temp, '\0', 256);

    if((ret = fread(cpu_id_temp, 1, 256, cpu_id_str)) == 0) {

        perror("fread\n");
        return NULL;
    } //printf("dmidecode -t 4 is: %s\n", cpu_id_temp);

    while((ret = memcmp(cpu_id_temp, cpu_id_flag, 3)) != 0)
        *cpu_id_temp++;

    char *cpu_id;
    cpu_id = (char *)malloc(32);
    memset(cpu_id, '\0', 32);
    memcpy(cpu_id, cpu_id_temp + 3, 24);
    //printf("cpu_id is: %s\n", cpu_id);
    return cpu_id;
}

char *get_bsbd_sn(void) {

    int ret = 0;
    FILE *bsbd_sn_str;
    if((bsbd_sn_str = popen("dmidecode -s baseboard-serial-number","r")) == NULL) {

        printf("getting bsbd_sn failed\n");
        return NULL;
    }

    char *bsbd_sn;
    bsbd_sn = (char *)malloc(SIZE);
    memset(bsbd_sn, '\0', SIZE);

    if((ret = fread(bsbd_sn, 1, SIZE - 1, bsbd_sn_str)) == 0) {

        perror("fread\n");
        return NULL;
    } //printf("bsbd_sn is: %s", bsbd_sn);
    return bsbd_sn;
}

char *id_concatenate(char *cpu_id, char *bsbd_sn) {

    char *temp;
    temp = (char *)malloc(SIZE);

    memset(temp, '\0', SIZE);
    char *id = (char *)temp;

    while(*bsbd_sn != '\n') *temp++ = *bsbd_sn++;
    while(*cpu_id != '\0') *temp++ = *cpu_id++;

    //printf("id encrypted is \"%s\" \n", id);
    return id;
}

char *usr_pub_en(char *id, char *usr_pub_path) {

    FILE *usr_pub_file;
    if((usr_pub_file = fopen(usr_pub_path, "r")) == NULL) {

        printf("open usr_pub.key failed\n");
        return NULL;
    }


    RSA *usr_pub;
    if((usr_pub = PEM_read_RSA_PUBKEY(usr_pub_file, NULL, NULL, NULL)) == NULL) {

        ERR_print_errors_fp(stdout);
        return NULL;
    }

    char *id_en;
    id_en = (char *)malloc(RSA_size(usr_pub));
    memset(id_en, '\0', RSA_size(usr_pub));

    if(RSA_public_encrypt(RSA_size(usr_pub), (u_char *)id, (u_char *)id_en, usr_pub, RSA_NO_PADDING) < 0)
        return NULL;

    fclose(usr_pub_file);
    printf("please send this id_file to the manufacturer, and get the liscence to startup.\n");

    FILE *id_en_file;
    if((id_en_file = fopen("/home/light/id_en_file", "w")) == NULL) {
        printf("creating id_en_file failed\n");
        return NULL;
    }

    fwrite(id_en, 1, RSA_size(usr_pub), id_en_file);
    fclose(id_en_file);
    free(usr_pub);

    return id_en;
}

char *mfr_pub_de(FILE *liscence_file, char *mfr_pub_path) {

    int ret = 0;
    char *liscence;
    liscence = (char *)malloc(SIZE);
    memset(liscence, '\0', SIZE);
    if((ret = fread(liscence, 1, SIZE, liscence_file)) == 0) {

        perror("fread");
        return  NULL;
    }
    fclose(liscence_file);

    FILE *mfr_pub_file;
    if((mfr_pub_file = fopen(mfr_pub_path, "r")) == NULL) {

        printf("open mfr_pub.key failed\n");
        return NULL;
    }

    RSA *mfr_pub;
    if((mfr_pub = PEM_read_RSA_PUBKEY(mfr_pub_file, NULL, NULL, NULL)) == NULL) {

        ERR_print_errors_fp(stdout);
        return NULL;
    }

    char *liscence_de;
    liscence_de = (char *)malloc(RSA_size(mfr_pub));
    memset(liscence_de, '\0', RSA_size(mfr_pub));

    if(RSA_public_decrypt(RSA_size(mfr_pub), (u_char *)liscence, (u_char *)liscence_de, mfr_pub, RSA_NO_PADDING) < 0)
        return NULL;

    free(mfr_pub);
    fclose(mfr_pub_file);
    //printf("liscence_de is \"%s\" \n", liscence_de);

    return liscence_de;
}

char *get_date(void) {

    int ret = 0;
    FILE *date_str;
    if((date_str = popen("date +%Y%m%d", "r")) == NULL) {

        printf("consulting date failed\n");
        return NULL;
    }

    char *date;
    date = (char *)malloc(8);
    memset(date, '\0', 8);

    if((ret = fread(date, 1, 8, date_str)) == 0) {

        perror("fread\n");
        return NULL;
    } //printf("system date is: %s\n", date);
    return date;
}

int main(void) {

    char *cpu_id = NULL;
    char *bsbd_sn = NULL;
    char *id = NULL;

    char *liscence_de;
    liscence_de = (char *)malloc(SIZE);
    memset(liscence_de, '\0', SIZE);

    cpu_id = get_cpu_id();
    bsbd_sn = get_bsbd_sn();
    id = id_concatenate(cpu_id, bsbd_sn);

    FILE *liscence_file;
    liscence_file = fopen(LISCENCE_PATH, "r");

    if(liscence_file == NULL) {

        printf("No liscence found: ");
        usr_pub_en(id, USR_PUB_PATH);

    } else {

        liscence_de = mfr_pub_de(liscence_file, MFR_PUB_PATH);

        char *date;
        date = (char *)malloc(10);
        memset(date, '\0', 10);
        date = get_date();

        char *liscence_date;
        liscence_date = (char *)malloc(10);
        memset(liscence_date, '\0', 10);
        memcpy(liscence_date, liscence_de, 8);
        //printf("authoried date is %s\n", liscence_date);

        if(strcmp(date, liscence_date) > 0) {
            printf("Exit: authorization expired\n");
            return -1;
        } else printf("valid authoried date\n");

        if(strcmp(id, liscence_de + 8) != 0) {

            printf("Exit: running on an invalid machine\n");
            return -1;
        } else printf("starting up...\n");
    }

    return 0;
}


