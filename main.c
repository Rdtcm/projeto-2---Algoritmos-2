#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <stdint.h>

#define MAXIMO_PALAVRAS 24
#define MAXIMO_COMBINACOES 8308824
#define TAMANHO_PALAVRAS 58

int Base64Encode(const unsigned char* buffer, size_t length, char** b64text) { 
	BIO *bio, *b64;
	BUF_MEM *bufferPtr;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); 
	BIO_write(bio, buffer, length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);

	*b64text = (*bufferPtr).data;
    
    if (bio == NULL || b64 == NULL || bufferPtr == NULL) {
    fprintf(stderr, "Memory allocation failed during Base64 encoding\n");
    return 1;
}
	return (0); 
}

char* ler_proxima_palavra(FILE *pont_dados) { //pega uma palavra do arquivo 
    static char palavra[100];
    if (fscanf(pont_dados, "%s", palavra) == 1) {
        return palavra;
    } else {
        return NULL;
    }
}

char* ler_proxima_palavra2(FILE *pont_dados) { //pega uma linha do arquivo
    static char linha[100];
    if (fgets(linha, sizeof(linha), pont_dados) != NULL) {
        strtok(linha, "\n");  //remove o '\n' da linha para que a hashe gerada seja a correta
        return linha;
    } else {
        return NULL;
    }
}

char* ler_proxima_palavra3(FILE *pont_dados) { //pega uma linha do arquivo
    static char linha[100];
    if (fgets(linha, sizeof(linha), pont_dados) != NULL) {
        strtok(linha, "\n");  //remove o '\n' da linha para que a hashe gerada seja a correta
        return linha;
    } else {
        return NULL;
    }
}

char* ler_proxima_palavra4(FILE *pont_dados) { //pega uma linha do arquivo
    static char linha[100];
    if (fgets(linha, sizeof(linha), pont_dados) != NULL) {
        strtok(linha, "\n");  //remove o '\n' da linha para que a hashe gerada seja a correta
        return linha;
    } else {
        return NULL;
    }
}

void guardar_possibilidades5(FILE *possibilidades, char name1[], char name2[], char name3[], char name4[], char name5[]) {
    fprintf(possibilidades, "%s %s %s %s %s\n", name1, name2, name3, name4, name5);
}
void guardar_possibilidades4(FILE *possibilidades, char name1[], char name2[], char name3[], char name4[]) {
    fprintf(possibilidades, "%s %s %s %s\n", name1, name2, name3, name4);
}
void guardar_possibilidades3(FILE *possibilidades, char name1[], char name2[], char name3[]) {
    fprintf(possibilidades, "%s %s %s\n", name1, name2, name3);
}
void guardar_possibilidades2(FILE *possibilidades, char name1[], char name2[]) {
    fprintf(possibilidades, "%s %s\n", name1, name2);
}
void guardar_possibilidades1(FILE *possibilidades, char name1[]) {
    fprintf(possibilidades, "%s\n", name1);
}

void guardar_hash(FILE *hashes, char hash_hex[]) {
    if (hashes != NULL) {
        fprintf(hashes, "%s\n", hash_hex);
    }
}

void guardar_ex(FILE *existe, char *exi) {
    if (existe != NULL) {
        fprintf(existe, "%s\n", exi);
    }
}

void guardar_linha(FILE *existe, int exi) {
    if (existe != NULL) {
        fprintf(existe, "%d\n", exi);
    }
}

void guardar_nome(FILE *existe, char *nome) {
    if (existe != NULL) {
        fprintf(existe, "%s:", nome);
    }
}

void gerar_combinacoes(char vetor_palavras[][TAMANHO_PALAVRAS], int n) { //gerando todas as possibilidades de senha
    int cont = 0;
    bool parar = false;

    FILE *possibilidades = fopen("todas_possibilidades.txt", "a");
    if (possibilidades == NULL) {
        printf("Erro ao abrir o arquivo para gravação de possibilidades!\n");
        return;
    }

    for (int tamanho = 1; tamanho <= 5 && !parar; tamanho++) { //for que define o tamanho da possibilidade, ex tamanho =1 "alho", tam = 2 "alho alho"
        for (int b = 0; b < n && !parar; b++) {
            if (tamanho == 1) {
                guardar_possibilidades1(possibilidades, vetor_palavras[b]);
                cont++;
                if (cont >= MAXIMO_COMBINACOES) { parar = true; break; }
            }

            for (int c = 0; c < n && !parar; c++) {
                if (tamanho == 2) {
                    guardar_possibilidades2(possibilidades, vetor_palavras[b], vetor_palavras[c]);
                    cont++;
                    if (cont >= MAXIMO_COMBINACOES) { parar = true; break; }
                }

                for (int d = 0; d < n && !parar; d++) {
                    if (tamanho == 3) {
                        guardar_possibilidades3(possibilidades, vetor_palavras[b], vetor_palavras[c], vetor_palavras[d]);
                        cont++;
                        if (cont >= MAXIMO_COMBINACOES) { parar = true; break; }
                    }

                    for (int e = 0; e < n && !parar; e++) {
                        if (tamanho == 4) {
                            guardar_possibilidades4(possibilidades, vetor_palavras[b], vetor_palavras[c], vetor_palavras[d], vetor_palavras[e]);
                            cont++;
                            if (cont >= MAXIMO_COMBINACOES) { parar = true; break; }
                        }

                        for (int f = 0; f < n && !parar; f++) {
                            if (tamanho == 5) {
                                guardar_possibilidades5(possibilidades, vetor_palavras[b], vetor_palavras[c], vetor_palavras[d], vetor_palavras[e], vetor_palavras[f]);
                                cont++;
                                if (cont >= MAXIMO_COMBINACOES) { parar = true; break; }
                            }
                        }
                    }
                }
            }
        }
    }
    fclose(possibilidades);
}

int retornar_linha_hash (FILE *hashes, FILE *senhas_quebradas) {

}

void gerar_hashes(unsigned char *hash, char *hash_hex, FILE *possibilidades_senhas, SHA512_CTX *ctx, FILE *hashes) { //gerando as hashes a partir do arquivo todas_possibilidades.txt
    char *linha;
    while ((linha = ler_proxima_palavra2(possibilidades_senhas)) != NULL) {
        SHA512_Init(ctx);
        SHA512_Update(ctx, linha, strlen(linha));
        SHA512_Final(hash, ctx);
        char *base64encoded;
        Base64Encode(hash, 64, &base64encoded);

        
        
        guardar_hash(hashes, base64encoded);
    }
}

void remover_nome_e_pontos(FILE *arquivo_original, FILE *arquivo_limpo,FILE *nomes) {
    char linha[200];

    while (fgets(linha, sizeof(linha), arquivo_original) != NULL) {
        char * tes = strtok(linha, ":");
        if (tes != NULL) {
            fprintf(nomes, "%s\n", tes);
        }
        tes = strtok(NULL, ":");
        if (tes != NULL) {
            fprintf(arquivo_limpo, "%s", tes);
        }
    }
    
}

int contar_linhas(FILE *file) { // funcao para contar as linhas do arquivo txt
  int linhas = 0; 
  char ch;
  while (!feof(file)) { //feof retorna um valor diferente de 0 se tentar ler apos o arquivo
    ch = fgetc(file);
    if (ch == '\n') {
      linhas++;
    }
  }
  return linhas;
}

int verificar_palavra(FILE *sem_acentos, char palavra[]) { // verifica se a palavra digitada esta no arquivo sem acentos.txt
    char acumular_conteudo_linha[90];
    int cont = 0;
    rewind(sem_acentos); 

    while (fgets(acumular_conteudo_linha, sizeof(acumular_conteudo_linha),sem_acentos)) { 
    cont++;
    acumular_conteudo_linha[strcspn(acumular_conteudo_linha, "\n")] = 0; 
        if (strcmp(acumular_conteudo_linha, palavra) == 0) { 
      return cont; // Palavra encontrada
        }
    } 
    return -1; // caso nao encontre a palavra no arquivo
}


int main(void) {
    FILE *words = fopen("palavras.txt", "r");
    if (words == NULL) {
        printf("Erro ao abrir o arquivo de palavras!\n");
        return 1;
    }

    char vetor_palavras[MAXIMO_PALAVRAS][TAMANHO_PALAVRAS] = {{""}};
    char *palavra;

    for (int i = 0; i < MAXIMO_PALAVRAS; i++) {
        palavra = ler_proxima_palavra(words);
        if (palavra != NULL) {
            strcpy(vetor_palavras[i], palavra);
        } else { break; }
    }

    fclose(words);

    int n = MAXIMO_PALAVRAS;

    gerar_combinacoes(vetor_palavras, n); //gera todas as combinacoes de senhas possiveis com base no arquivo de palavras

    FILE *hashes = fopen("hashes.txt", "a");
    FILE *possibilidades_senhas = fopen("todas_possibilidades.txt", "r");
    
    if (hashes == NULL || possibilidades_senhas == NULL) {
        printf("Erro ao abrir o arquivo hashes.txt ou o arquivo todas_possibilidades.txt!\n");
        fclose(hashes);
        return 1;
    }

    SHA512_CTX ctx;
    unsigned char hash[SHA512_DIGEST_LENGTH];
    char hash_hex[SHA512_DIGEST_LENGTH * 2 + 1];

    gerar_hashes(hash, hash_hex, possibilidades_senhas, &ctx, hashes);

    fclose(hashes);
    fclose(possibilidades_senhas); 

    FILE *hash_usuario_original = fopen("usuarios_senhascodificadas.txt", "r");
    FILE *hash_usuario_limpo = fopen("usuarios_senhacodificado_limpo.txt", "a");
    FILE *nomes = fopen("nomes.txt", "a");
    if (hash_usuario_original == NULL || hash_usuario_limpo == NULL || nomes == NULL) {
        printf("Erro ao abrir o arquivo!\n");
        return 1;
    }

    remover_nome_e_pontos(hash_usuario_original, hash_usuario_limpo,nomes);

    fclose(hash_usuario_original);
    fclose(hash_usuario_limpo);
    fclose(nomes);

    FILE *hashes_file = fopen("hashes.txt", "r");
    FILE *hash_usuario = fopen("usuarios_senhacodificado_limpo.txt", "r");
    FILE *existe_txt = fopen("existe.txt", "a");
    FILE *td_possi = fopen("todas_possibilidades.txt", "r");
    FILE *linhatx = fopen("linha.txt", "a");
    FILE *nomes2 = fopen("nomes.txt", "r");
    FILE *senhas_quebradas = fopen("senhas_quebradas.txt", "a");

    if (hashes_file == NULL || hash_usuario == NULL || existe_txt == NULL || td_possi == NULL || linhatx == NULL || nomes2 == NULL || senhas_quebradas == NULL) {
        printf("ERRO AO TENTAR ABRIR OS ARQUIVOS!\n");
        return 1;
    }

   

    int ex;
    char *hashveri;
    char *hashveri2;
    char *nome;
    for(int i=0 ; i < 22 ; i++){
        ex=0;
        hashveri = ler_proxima_palavra3(hash_usuario);
        nome = ler_proxima_palavra4(nomes2);
        printf("%s \n", hashveri);
        guardar_nome(existe_txt,nome); 
        ex = verificar_palavra(hashes_file,hashveri);
        guardar_linha(linhatx,ex); //guarda a linha da hash encontrada no arquivo linha.txt
        if (ex  >= 0) {
            for (int j = 1 ; j <= ex ;j++) {
                hashveri2 = ler_proxima_palavra3(td_possi);
            }
        guardar_ex(existe_txt,hashveri2);    
        } else if ( ex == -1) {   
            guardar_ex(existe_txt,"Não está presente");    
        }
        rewind(td_possi);
        
    }
    
    fclose(senhas_quebradas);
    fclose(hashes_file);
    fclose(hash_usuario); 
    return 0;
}
