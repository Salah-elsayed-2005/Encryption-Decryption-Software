#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define rows 5
#define cols 5



//Caeser Prototypes
void Caeser(void);
void caeser_encryption(char p,char c,int k);
void caeser_decryption(char c,char p,int k);



//Playfair Prototypes
void Playfairr(void);
void remove_dups(char key[]);
void read_key(char key[]);
void insert_key(char mat[rows][cols], char key[]);
void read_plaintext(char p[],int *sizePtr);
void p_duplicates_encr(char p[],int size,int *sizePtr);
void p_duplicates(char p[],int size,int *sizePtr);
void find_position(char mat[rows][cols],char p1,char p2,int *i1,int *j1, int *i2, int *j2);
/// Encryption functions ///
void horizontal_shift_encr(char mat[rows][cols],char *p1,char *p2,int i1,int j1, int i2, int j2);
void vertical_shift_encr(char mat[rows][cols],char *p1,char *p2,int i1,int j1, int i2, int j2);
void rectangle_shift(char mat[rows][cols],char *p1,char *p2,int i1,int j1, int i2, int j2);
void playfair_encryption(char mat[rows][cols], char p[], int size);
/// Decryption fucntions ///
void horizontal_shift_decr(char mat[rows][cols],char *p1,char *p2,int i1,int j1, int i2, int j2);
void vertical_shift_decr(char mat[rows][cols],char *p1,char *p2,int i1,int j1, int i2, int j2);
void playfair_decryption(char mat[rows][cols], char p[], int size);



//RSA Prototypes
int RSA(void);
int Ge(int t);
int Gd(int e,int t);
int IsPrime(int e);
int MakePrime(int pri);
int Rando(const char pass[]);
void RsaEnc(long int e,long int n);
void RsaDec(int d,long int n);
int RSAToFile(void);
int RSAReadFile(void);

//The Main function

int main(){
    int option;
    printf("\n ___________________________________\n");
    printf("|   Encryption/Decryption Program   |\n");
    printf("|                                   |\n");
    printf("|Fouad Ahmed Hashesh     (22-101062)|\n");
    printf("|Abdulrahman Abougendia  (22-101194)|\n");
    printf("|Kareem Yasser           (22-101124)|\n");
    printf("|Salah Eldin Elsayed     (22-101188)|\n");
    printf("|___________________________________|\n");
    while(1){
        printf("\nChoose Your Algorithm:\n \n1.Caeser Cipher\n2.Playfair Cipher\n3.RSA Cipher\n4.Exit\n___________________________________\nEnter your choice : ");
        scanf("%d",&option);


        switch(option){
            case 1:
                printf("\nCaeser Cipher\n");
                fflush(stdin);
                Caeser();
                printf("___________________________________\n");
                break;
            case 2:
                printf("\nPlayfair Cipher\n");
                fflush(stdin);
                Playfairr();
                printf("___________________________________\n");
                break;
            case 3:
                printf("\nRSA Cipher\n");
                fflush(stdin);
                RSA();
                printf("___________________________________\n");
                break;
            case 4:
                printf("** GoodBye **\n");
                return 0;
            default:
                printf("Please enter a valid choice");

        }}}





//////////////////////////RSA//////////////////////////
//   _____   _____
//  |  __ \ / ____|  /\             By: Salah Eldin Elsayed  &  Fouad Ahmed Hashesh
//  | |__) | (___   /  \                    (22-101188)             (22-101062)
//  |  _  / \___ \ / /\ \
//  | | \ \ ____) / ____ \
//  |_|  \_\_____/_/    \_\
////////////////////////////


//Global vars (RSA)
char rsaarr[999] = {0};
int rsacount;
long int rsatemp[999],en[999],m[999];


int RSA(void) {
    rsacount = 0;
    int e, t, p, q, d, n,mode=0;
    char passwd[10] = {0};

    printf("\nChoose:\n1.Encryption\n2.Decryption\n___________________________________\nEnter your choice : ");
    scanf("%d",&mode);
    fflush(stdin);

    switch(mode){
        case 1:

            printf("Enter plaintext: ");

            //store chars in array
            for (int i = 0; i < 999; ++i) {

                if (rsaarr[i - 1] == '\n')
                    break;
                else {
                    scanf("%c", &rsaarr[i]);
                    //the count ind. the num of char
                    rsacount++;
                }

            }
            mode=0;
            printf("___________________________________\nChoose:\n1.Manually enter \"p\" & \"q\"\n2.Generate from password\n___________________________________\nEnter your choice : ");
            scanf("%d",&mode);
            fflush(stdin);


            switch(mode){
                case 1:
                    printf("\nEnter \"p\" value : ");
                    scanf("%d",&p);
                    fflush(stdin);
                    printf("\nEnter \"q\" value : ");
                    scanf("%d",&q);
                    fflush(stdin);

                    if((IsPrime(p)&&IsPrime(q))&&p!=q)break;
                    else {printf("\nINVALID VALUES... RESETTING\n");return 0;}

                case 2:
                    printf("\nEnter password with maximum of 8 char: ");
                    for (int i = 0; i <= 8; ++i) {

                        if (passwd[i - 1] == '\n')
                            break;
                        else {
                            scanf("%c", &passwd[i]);
                        }
                    }
                    p = MakePrime(Rando(passwd));
                    q = 17;
                    if(q==p)q=21;
                    break;
                default:
                    printf("\nINVALID VALUES.. RESETTING\n");
                    return 0;


            }
            printf("p: %d \n", p);
            printf("q: %d \n", q);
            n = p * q;
            t = (p - 1) * (q - 1);
            e = Ge(t);
            d = Gd(e,t);

            printf("n: %d\n",n);
            printf("t: %d\n",t);
            printf("e: %d\n",e);
            printf("d: %d\n", d);

            RsaEnc(e, n);
            RsaDec(d, n);
            RSAToFile();
            break;


        case 2:
            mode=0;
            printf("\nChoose:\n1.Enter ciphered message\n2.Provide encrypted file\n___________________________________\nEnter your choice : ");
            scanf("%d",&mode);
            fflush(stdin);

            switch (mode) {
                case 1:
                    printf("Enter ciphertext and termenate with \"-1\": ");

                    //store chars in array
                    for (int i = 0; i < 999; ++i) {

                        if (en[i - 1] == -1)
                            break;
                        else {
                            scanf("%ld", &en[i]);
                        }
                    }
                    break;

                case 2:
                    RSAReadFile();
                    break;

                default:
                    printf("\nINVALID VALUES.. RESETTING\n");
                    return 0;
            }




            mode=0;

            printf("\nChoose:\n1.Manually enter \"d\" & \"n\"\n2.Enter password\n___________________________________\nEnter your choice : ");
            scanf("%d",&mode);
            fflush(stdin);


            switch(mode){
                case 1:
                    printf("\nEnter \"d\" value: ");
                    scanf("%d",&d);
                    fflush(stdin);
                    printf("\nEnter \"n\" value: ");
                    scanf("%d",&n);
                    fflush(stdin);
                    RsaDec(d,n);
                    break;
                case 2:
                    printf("\nEnter your password : ");
                    for (int i = 0; i <= 8; ++i) {

                        if (passwd[i - 1] == '\n')
                            break;
                        else {
                            scanf("%c", &passwd[i]);
                        }
                    }
                    p = MakePrime(Rando(passwd));
                    q = 17;
                    if(q==p)q=23;
                    printf("p: %d \n", p);
                    printf("q: %d \n", q);
                    n = p * q;
                    t = (p - 1) * (q - 1);
                    e = Ge(t);
                    d = Gd(e,t);

                    printf("n: %d\n",n);
                    printf("t: %d\n",t);
                    printf("e: %d\n",e);
                    printf("d: %d\n",d);
                    RsaDec(d,n);
                    break;

                default:
                    printf("\nINVALID VALUES.. RESETTING\n");
                    return 0;
            }

        default:
            return 0;


    }






    return 0;

}


int Ge(int t) {
    int e = 0;

    for (int i = 3; i <= t; i += 2) {
        e = i;
        if (IsPrime(e) && t % e != 0) break;
    }
    return e;
}

int IsPrime(int e) {
    if(e<=1) return 0;
    int cond = 1;

    for (int i = 2; i <= e / 2; ++i) {
        if (e % i == 0) {
            cond = 0;
            break;
        }

    }

    return cond;
}

int MakePrime(int pri) {
    while (!(IsPrime(pri))) {

        if (pri <= 41) pri++;
        else pri--;
    }

    return pri;

}

int Rando(const char pass[]) {

    int r = 0;

    for (int i = 0; i <= 7; i++){
        r = r + pass[i];
    }

    r %= (pass[0] / 3);

    if (r <= 5){r = 23;}
    return r;
}

int Gd(int e,int t){
    int k = 1;
    while (1) {
        if (fmod(((k * t) + 1), e) == 0)
            break;
        else
            k++;
    }

    return (((k * t) + 1) / e);

}

void RsaEnc(long int e,long int n) {

    long int ct,k,i=0;

    while(i<(rsacount-1)) {
        k=1;
        m[i]=(((int)rsaarr[i])-96);

        for (int j=0;j<e;j++) {
            k=k*m[i];
            k=k%n;
        }

        rsatemp[i]=k;
        ct=k+96;
        en[i]=ct;
        i++;
    }

    en[i]=-1;


    printf("\nTHE ENCRYPTED MESSAGE IS : \n");


    for (i=0;en[i]!=-1;i++)
        printf("%ld ",en[i]);
    printf("\n");

}


void RsaDec(int d,long int n) {

    long int i=0,pt,ct,k;

    while(en[i]!=-1) {
        ct=(en[i]-96);
        k=1;

        for (int j=0;j<d;j++) {
            k=k*ct;
            k=k%n;
        }

        pt=k+96;
        m[i]=pt;
        i++;
    }
    m[i]=-1;

    printf("\nTHE DECRYPTED MESSAGE IS : \n");
    for (i=0;m[i]!=-1;i++)
        printf("%c",(int)m[i]);
    printf("\n");
}

int RSAToFile(void){
    int ans;
    printf("___________________________________\nWould you like to output the results to a file ?\n1.Yes\n2.No\nChoose: ");
    scanf("%d",&ans);
    fflush(stdin);


    if(ans==1){
        char name[50];
        int co=0;
        printf("\nEnter file name: ");
        for (int i = 0; i <= 50; ++i) {

            if (name[i - 1] == '\n')
                break;
            else {
                scanf("%c", &name[i]);co++;
            }

        }name[co-1]='\0';
        FILE *fp;
        fp = fopen (name, "a");
        for(int i=0;en[i]!=-1;i++){
            fprintf(fp,"%ld ",en[i]);
        }fprintf(fp,"%d",-1);fclose(fp);
    }
    return 0;
}

int RSAReadFile(void){
    char name[50];
    int co=0;
    printf("___________________________________\nEnter file name: ");
    for (int i = 0; i <= 50; ++i) {

        if (name[i - 1] == '\n')
            break;
        else {
            scanf("%c", &name[i]);co++;
        }

    }name[co-1]='\0';
    fflush(stdin);

    FILE* ptr;
    ptr = fopen(name, "r");

    if (NULL == ptr) {
        printf("File can\'t be opened ... EXITING\n");
        exit(1);
    }

    for (int i = 0; i < 999; ++i) {

        if (en[i - 1] == -1)
            break;
        else {
            fscanf(ptr,"%ld", &en[i]);
            rsacount++;
        }

    }en[rsacount-1]=-1;


    fclose(ptr);

    return 0;
}










///////////////////////////////////////////PLAYFAIR/////////////////////////////////////////////////
//   _____  _             ______    _
//  |  __ \| |           |  ____|  (_)
//  | |__) | | __ _ _   _| |__ __ _ _ _ __              By: Abdulrahman Abougendia && Kareem Yasser
//  |  ___/| |/ _` | | | |  __/ _` | | '__|                       (22-101194)          (22-101124)
//  | |    | | (_| | |_| | | | (_| | | |
//  |_|    |_|\__,_|\__, |_|  \__,_|_|_|
//                  __/ |
//                 |___/
////////////////////////////////////////////////////////////////////////////////////////////////


void Playfairr(void){
    int choice;
    char key[1000],a;
    printf("\n1.Encryption\n2.Decryption\n___________________________________\nEnter your choice : ");
    scanf("%d",&choice);
    scanf("%c",&a);
    char mat[rows][cols];
    for(int i=0;i<rows;i++){
        for(int j=0;j<cols;j++){
            mat[i][j]='#';
        }
    }
    switch(choice){
        case 1:

            for(int i=0;i<1000;i++)
                key[i]='#';
            printf("Enter key : ");
            read_key(key);
            insert_key(mat,key);
            char p[1000000];
            int pSize=0;
            printf("Enter Plaintext : ");
            read_plaintext(p,&pSize);

            int pSizeX=0;
            p_duplicates(p,pSize,&pSizeX); // p : plaintext, pSize : plaintext size before adjusting, pSizeX : plaintext size after adjusting
            playfair_encryption(mat,p,pSizeX);
            printf("Ciphertext : ");
            for(int i=0;i<pSizeX;i++){
                printf("%c",p[i]);
            }
            break;
        case 2:

            for(int i=0;i<1000;i++)
                key[i]='#';
            printf("Enter key : ");
            read_key(key);
            insert_key(mat,key);

            pSize=0;
            printf("Enter Ciphertext : ");
            read_plaintext(p,&pSize);
            pSizeX=0;
            p_duplicates(p,pSize,&pSizeX); // p : plaintext, pSize : plaintext size before adjusting, pSizeX : plaintext size after adjusting
            playfair_decryption(mat,p,pSizeX);
            printf("Plaintext : ");
            for(int i=0;i<pSizeX;i++){
                if(p[i]=='X'&& i%2!=0)
                    continue;
                printf("%c",p[i]);
            }
            break;
        default :
            printf("Enter a valid option\n");
    }
}/// *End of main * ///
void remove_dups(char key[]){
    int size=1000;
    for(int i=0;i<size;i++){
        for(int j=i+1;j<size;j++){
            if(key[i]==key[j]){
                for(int k=j;k< size - 1;k++){
                    key[k]=key[k+1];
                }
                /* Decrement size after removing duplicate element */
                size--;
                /* If shifting of elements occur then don't increment j */
                j--;
            }
        }
    }
}
void read_key(char key[]){
    int size=0;
    char temp='@';
    for(int i=0;i<1000;i++){
        temp=getchar();
        if(temp=='\n')
            break;
        key[i]=temp;
        size++;
        if(key[i]>='a' && key[i]<='z'){ //uppercase
            key[i]-=32;
        }
    }

    for(int i=0;i<size;i++){
        if(key[i]==' '){ //remove spaces
            for(int j=i;j<size;j++){
                key[j]=key[j+1];
            }
            size--;
        }
    }
    char f='A'; //fill
    for(int i=size;i<1000;i++){
        if(f!='J'){
            key[i]=f;
        }
        else{
            i--;
        }
        f++;
        if(key[i]=='Z')
            break;
    }
    remove_dups(key);
}
void insert_key(char mat[rows][cols], char key[]){
    int k=0;
    for(int i=0;i<rows;i++){
        for(int j=0;j<cols;j++){
            mat[i][j]=key[k];
            k++;
        }
    }

}

void read_plaintext(char p[],int *sizePtr){
    int i=0,size=0;
    char temp='#';
    while(1){
        scanf("%c",&temp);
        if(temp=='\n')
            break;
        if(temp>='a' && temp<='z')
            temp-=32;
        p[i]=temp;
        i++;
        size++;
    }
    *sizePtr=size;
}
void p_duplicates(char p[],int size,int *sizePtr){
    for(int i=0;i<size;i++){
        if(p[i]==' '){ // sa la
            for(int j=i;j<size;j++){
                p[j]=p[j+1];
            }
            size--;
        }
    }
    for(int i=0;i<size-1;i++){
        if(p[i]==p[i+1] && i%2==0){ // if there is a duplicate and the position is even
            for(int j=size;j>i+1;j--){ // make room for the fill
                p[j]=p[j-1];
            }
            p[i+1]='X';
            size++;
        }
    }
    if(size%2!=0){
        p[size]='X';
        size++;
    }
    *sizePtr=size; // update size in main
}
void find_position(char mat[rows][cols],char p1,char p2,int *i1,int *j1, int *i2, int *j2){
    for(int i=0;i<rows;i++){
        for(int j=0;j<cols;j++){
            if(p1=='J')    // i/j are in the same cell
                p1='I';
            if(p2=='J')
                p2='I';
            if(mat[i][j]==p1){
                *i1=i;
                *j1=j;
            }
            if(mat[i][j]==p2){
                *i2=i;
                *j2=j;
            }
        }
    }

}
/// * Encryption fuctions * ///
void horizontal_shift_encr(char mat[rows][cols],char *p1,char *p2,int i1,int j1, int i2, int j2){
    if(j1==4)  // reset if it reached the end
        j1=-1;
    *p1=mat[i1][j1+1];
    if(j2==4)  // reset if it reached the end
        j2=-1;
    *p2=mat[i2][j2+1];

}
void vertical_shift_encr(char mat[rows][cols],char *p1,char *p2,int i1,int j1, int i2, int j2){
    if(i1==4)  // reset if it reached the end
        i1=-1;
    *p1=mat[i1+1][j1];
    if(i2==4)   // reset if it reached the end
        i2=-1;
    *p2=mat[i2+1][j2];
}
void rectangle_shift(char mat[rows][cols],char *p1,char *p2,int i1,int j1, int i2, int j2){
    *p1=mat[i1][j2];
    *p2=mat[i2][j1];
}
void playfair_encryption(char mat[rows][cols], char p[], int size){
    int i1; int j1; int i2; int j2;
    for(int i=0;i<size-1;i+=2){
        find_position(mat,p[i],p[i+1],&i1,&j1,&i2,&j2);
        if(i1==i2){
            horizontal_shift_encr(mat,&p[i],&p[i+1],i1,j1,i2,j2);
        }
        else if(j1==j2){
            vertical_shift_encr(mat,&p[i],&p[i+1],i1,j1,i2,j2);
        }
        else{
            rectangle_shift(mat,&p[i],&p[i+1],i1,j1,i2,j2);
        }

    }
}
/// * Decryption functions * ///
void horizontal_shift_decr(char mat[rows][cols],char *p1,char *p2,int i1,int j1, int i2, int j2){
    if(j1==0)  // reset if it reached the start
        j1=5;
    *p1=mat[i1][j1-1];
    if(j2==0)  // reset if it reached the start
        j2=5;
    *p2=mat[i2][j2-1];
}
void vertical_shift_decr(char mat[rows][cols],char *p1,char *p2,int i1,int j1, int i2, int j2){
    if(i1==0)  // reset if it reached the start
        i1=5;
    *p1=mat[i1-1][j1];
    if(i2==0)   // reset if it reached the start
        i2=5;
    *p2=mat[i2-1][j2];
}
void playfair_decryption(char mat[rows][cols], char p[], int size){
    int i1; int j1; int i2; int j2;
    for(int i=0;i<size-1;i+=2){
        find_position(mat,p[i],p[i+1],&i1,&j1,&i2,&j2);
        if(i1==i2){
            horizontal_shift_decr(mat,&p[i],&p[i+1],i1,j1,i2,j2);
        }
        else if(j1==j2){
            vertical_shift_decr(mat,&p[i],&p[i+1],i1,j1,i2,j2);
        }
        else{
            rectangle_shift(mat,&p[i],&p[i+1],i1,j1,i2,j2);
        }
    }
}


/*
  0 1 2 3 4
0 s a l h b  s-->h ---> mat[0][0] j1=j2 -----> mat[0][3]
1 c d e f g  f ---> mat[1][3] j2=j1 -----> mat[1][0]
2 i k m n o
3 p q r t u     sa
4 v w x y z     s ---> a
                a ---> l
0 1  2 3  4 5  6 7
h o  o l  o x  C S

*/


















///////////////////////////////////Caeser/////////////////////////////////////
//   _____
//  / ____|
//  | |     __ _  ___  ___  ___ _ __               By: Abdulrahman Abougendia && Kareem Yasser
//  | |    / _` |/ _ \/ __|/ _ \ '__|                         (22-101194)         (22-101124)
//  | |___| (_| |  __/\__ \  __/ |
//   \_____\__,_|\___||___/\___|_|
///////////////////////////////////////////////////////////////////////////////





void Caeser(void){
    char p='\0',c='\0',a;
    int k;  //key
    int choice;
    printf("\nChoose:\n1.Encryption \n2.Decryption\n___________________________________\nYour choice : ");
    scanf("%d",&choice);



    switch (choice)
    {
        case 1:
            printf("\nEnter encryption key : ");
            scanf("%d",&k);
            k%=26;  //making the key between 0 and 26
            scanf("%c",&a);
            printf("Enter plaintext : ");
            caeser_encryption(p,c,k);
            break;
        case 2:
            printf("Enter decryption key : ");

            scanf("%d",&k);
            k%=26;  //making the key between 0 and 26
            scanf("%c",&a);
            printf("Enter ciphertext : ");
            caeser_decryption(p,c,k);
            break;
        default:
            printf("Choose valid option !\n");
    }
}




void caeser_encryption(char p,char c,int k)
{
    char a[1000000]={'a'};
    int i=0;
    int k_temp;
    while(1){
        k_temp=k;
        scanf("%c",&p);
        if(p=='\n')
            break;
        if(p>='A' && p<='Z'){
            if((p+k)>'Z'){
                k_temp=(p+k_temp)-'Z';
                p='@';
            }
            else if((p+k_temp)<'A'){
                k_temp=(p+k_temp)-'A';
                p='[';
            }
            c=(p+k_temp);
        }
        else if(p>='a' && p<='z'){
            if((p+k_temp)>'z'){
                k_temp=(p+k_temp)-'z';
                p='`';
            }
            else if((p+k_temp)<'a'){
                k_temp=(p+k_temp)-'a';
                p='{';
            }
            c=(p+k_temp);
        }
        else{
            c=p;
        }
        a[i]=c;
        i++;
    }
    printf("Ciphertext      : ");
    for(int j=0;j<i;j++){
        printf("%c",a[j]);
    }
    printf("\n");
}


void caeser_decryption(char c,char p,int k) {
    char a[1000000] = {'a'};
    k *= (-1); //decryption key
    int i = 0;
    int k_temp;
    while (1) {
        k_temp = k;
        scanf("%c", &p);
        if (p == '\n')
            break;
        if (p >= 'A' && p <= 'Z') {
            if ((p + k_temp) > 'Z') {
                k_temp = (p + k_temp) - 'Z';
                p = '@';
            } else if ((p + k_temp) < 'A') {
                k_temp = (p + k_temp) - 'A';
                p = '[';
            }
            c = (p + k_temp);
        } else if (p >= 'a' && p <= 'z') {
            if ((p + k_temp) > 'z') {
                k_temp = (p + k_temp) - 'z';
                p = '`';
            } else if ((p + k_temp) < 'a') {
                k_temp = (p + k_temp) - 'a';
                p = '{';
            }
            c = (p + k_temp);
        } else {
            c = p;
        }
        a[i] = c;
        i++;
    }
    printf("\nPlaintext      : ");
    for (int j = 0; j < i; j++) {
        printf("%c", a[j]);
    }
}
