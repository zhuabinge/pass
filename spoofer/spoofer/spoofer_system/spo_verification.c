#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "spoofer.h"
#include "../spoofer_pool/spo_pool.h"


#define LISCENCE_EN_PATH "/home/lele/Template/liscence_en_file"
#define USR_PUB_PATH "/home/lele/Template/usr_pub.key"
#define MFR_PUB_PATH "/home/lele/Template/mfr_pub.key"
#define ID_EN_FILE_PATH "/home/lele/Template/id_en_file"
#define SIZE 1024

typedef struct spo_id_s
{
    char *cpu;
    char *bsbd;
    char *date;
    char *id;
    char *lisn;
    u_char *id_en;
    u_char *lisn_de;
} spo_id_t;

static SPO_RET_STATUS spo_verification_init(spo_id_t *spo_id)
{
    spo_id->bsbd = spo_calloc(SIZE);
    spo_id->cpu = spo_calloc(SIZE);
    spo_id->date = spo_calloc(SIZE);
    spo_id->id = spo_calloc(SIZE);
    spo_id->lisn = spo_calloc(SIZE);
    spo_id->id_en = spo_calloc(SIZE);
    spo_id->lisn_de = spo_calloc(SIZE);

    return SPO_OK;
}

static SPO_RET_STATUS  spo_get_bsbd(spo_id_t *spo_id)
{
    FILE *bsbd_sn;
    bsbd_sn = popen("dmidecode -s baseboard-serial-number", "r");

    fread(spo_id->bsbd, 1, SIZE, bsbd_sn);

    return SPO_OK;
}

static SPO_RET_STATUS  spo_get_cpu_id(spo_id_t *spo_id)
{
    FILE *cpu_id;
    char *flag = "ID:A";
    char *tmp;

    cpu_id = popen("dmidecode -t 4", "r");

    tmp = spo_calloc(SIZE);

    fread(tmp, 1, SIZE, cpu_id);

    while(memcmp(tmp, flag, 3) != 0) *tmp++;

    memcpy(spo_id->cpu, tmp + 3, 24);

    return SPO_OK;
}


static SPO_RET_STATUS spo_id_cat(spo_id_t *spo_id)
{
    char *tmp;
    tmp = spo_calloc(SIZE);
    spo_id->id = tmp;

    while(*spo_id->bsbd != '\n') *tmp++ = *(spo_id->bsbd)++;
    while(*spo_id->cpu != '\0') *tmp++ = *(spo_id->cpu)++;
    strcat(spo_id->id, "__bodao_youmaiba");

    printf("id encrypted----%s----\n", spo_id->id);

    return SPO_OK;
}


static SPO_RET_STATUS spo_get_date(spo_id_t *spo_id)
{
    FILE *date;

    date = popen("date +%Y%m%d", "r");

    fread(spo_id->date, 1, 8, date);

    return SPO_OK;
}

static SPO_RET_STATUS spo_usr_pub_en(spo_id_t *spo_id)
{
    FILE *usr_pub_file;
    FILE *id_en_file;
    RSA *usr_pub;

    usr_pub_file = fopen(USR_PUB_PATH, "r");

    usr_pub = PEM_read_RSA_PUBKEY(usr_pub_file, NULL, NULL, NULL);
    RSA_public_encrypt(RSA_size(usr_pub), (u_char *)spo_id->id, spo_id->id_en, usr_pub, RSA_NO_PADDING);

    id_en_file = fopen(ID_EN_FILE_PATH, "w");
    fwrite(spo_id->id_en, 1, RSA_size(usr_pub), id_en_file);

    printf("please send the id_en_file to the manufacturer, and get the liscence to startup.\n");
    fclose(usr_pub_file);
    fclose(id_en_file);
    spo_free(usr_pub);
    return SPO_OK;
}

static SPO_RET_STATUS spo_mfr_pub_de(spo_id_t *spo_id, FILE *lisn_file)
{
    FILE *mfr_pub_file;
    RSA *mfr_pub;

    mfr_pub_file = fopen(MFR_PUB_PATH, "r");

    fread(spo_id->lisn, 1, SIZE, lisn_file);

    mfr_pub = PEM_read_RSA_PUBKEY(mfr_pub_file, NULL, NULL, NULL);

    RSA_public_decrypt(RSA_size(mfr_pub), (u_char *)spo_id->lisn, spo_id->lisn_de, mfr_pub, RSA_NO_PADDING);

    fclose(mfr_pub_file);
    fclose(lisn_file);
    free(mfr_pub);
    return SPO_OK;
}

/*
 *
 *  check liscence
 *
 * */

SPO_RET_STATUS spo_verification()
{
    spo_id_t *spo_id;
    FILE *lisn_file;

    spo_id = spo_calloc(sizeof(spo_id_t));

    spo_verification_init(spo_id);

    spo_get_bsbd(spo_id);
    spo_get_cpu_id(spo_id);
    spo_id_cat(spo_id);

    lisn_file = fopen(LISCENCE_EN_PATH, "r");

    if(lisn_file == NULL) {
        printf("No liscence found\n");
        spo_usr_pub_en(spo_id);
        return SPO_FAILURE;
    } else {

        spo_mfr_pub_de(spo_id, lisn_file);
        spo_get_date(spo_id);

        if(memcmp(spo_id->date, spo_id->lisn_de, 8) > 0) {
            printf("Exit: authorization expired\n");
            return SPO_FAILURE;
        }

        if(strcmp(spo_id->id, (char *)spo_id->lisn_de + 8) != 0) {

            printf("Exit: running on an invalid machine\n");
            return SPO_FAILURE;
        }
    }

    return SPO_OK;
}
