#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <cstdlib>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <cassert>
#include <time.h>

#define null 0

using namespace std;

#ifdef __cplusplus
  #include "lua.hpp"
#else
  #include "lua.h"
  #include "lualib.h"
  #include "lauxlib.h"
#endif

#define null 0

#ifdef __cplusplus
extern "C"{
#endif


TFheGateBootstrappingSecretKeySet* key;

const TFheGateBootstrappingCloudKeySet* bk;

int bitsize = 16;
int integerbitsize = 16;
int fractionbitsize = 16;

struct Double{
	LweSample *integerpart;
	LweSample *fractionpart;
};


static void stackDump (lua_State *L) {
    int i;
    int top = lua_gettop(L);
    for (i = 1; i <= top; i++) {  
    int t = lua_type(L, i);
    switch (t) {

        case LUA_TSTRING:  
        printf("`%s'", lua_tostring(L, i));
        break;

        case LUA_TBOOLEAN:  
        printf(lua_toboolean(L, i) ? "true" : "false");
        break;

        case LUA_TNUMBER: 
        printf("%g", lua_tonumber(L, i));
        break;

        default:  
        printf("%s", lua_typename(L, t));
        break;

    }
    printf("  ");  
    }
    printf("\n");  
}

bool is_file_empty(std::ifstream& pFile)
{
    return pFile.peek() == std::ifstream::traits_type::eof();
}

//decrypts ciphertext in datatobedecrypted.txt and returns resulting integer
static int decryptinteger(lua_State *L){
    string line;
    int16_t int_answer = 0;
    FILE* secret_key = fopen("secret.key","rb");
    key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);
    const TFheGateBootstrappingParameterSet* params = key->params;

    LweSample* ciphertext = new_gate_bootstrapping_ciphertext_array(bitsize, params);
    const int32_t n = params->in_out_params->n;

    for(int i=0; i<16; i++){
        ifstream inputfile ("datatobedecrypted" + to_string(i)+ ".txt");
        if (is_file_empty(inputfile)){
            delete_gate_bootstrapping_secret_keyset(key);
            delete_gate_bootstrapping_ciphertext_array(bitsize, ciphertext);
            lua_pushnil(L);
            return 1;
        }
    }

    for (int i=0; i<16; i++) {
        ifstream inputfile ("datatobedecrypted" + to_string(i) + ".txt");
        for (int j=0; j<n; j++){
            getline(inputfile, line);
            ciphertext[i].a[j] = stoi(line);
        
        }
        getline(inputfile, line);
        ciphertext[i].b = stoi(line);
        getline(inputfile, line);
        ciphertext[i].current_variance = stod(line);
        inputfile.close();
    }
    //decrypt and rebuild the answer
    for (int i=0; i<16; i++) {
        int ai = bootsSymDecrypt(&ciphertext[i], key)>0;
        int_answer |= (ai<<i);
    }

    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_ciphertext_array(bitsize, ciphertext);


    lua_pushnumber(L, int_answer);
    return 1;
}


// decrypts given integer part of Double struct
int decryptIntegerpart(LweSample* input, TFheGateBootstrappingSecretKeySet* key){
    //decrypt and rebuild the 32-bit plaintext answer
    int int_answer = 0;
    for (int i=0; i<integerbitsize; i++) {
        int ai = bootsSymDecrypt(&input[i], key);
        int_answer |= (ai<<i);
    }
	return int_answer;
}

// decrypts given fractional part of Double struct
double decryptFractionpart(LweSample* input, TFheGateBootstrappingSecretKeySet* key){
	double result = 0;
    int counter = -1;
	for(int i=fractionbitsize-1;i>=0;i--)
	{
		int temp = bootsSymDecrypt(&input[i],key);
		result += temp * (pow(2, counter));
        counter--;
	}	
	return result;
}

// decrypts given Double struct
double decryptDouble(Double d, TFheGateBootstrappingSecretKeySet* key){
	double result;
	LweSample* integerpart = d.integerpart;
	LweSample* fractionpart = d.fractionpart;

	int decryptedintpart = decryptIntegerpart(integerpart, key);
	double decryptedfracpart = decryptFractionpart(fractionpart, key);

    result = decryptedintpart + decryptedfracpart;

    return result;
}

//encrypts given integer
static int encryptinteger(lua_State *L){
    int16_t plaintext = luaL_checknumber (L, 1);

    FILE* secret_key = fopen("secret.key","rb");
    key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);

	LweSample *ciphertext = new_gate_bootstrapping_ciphertext_array(bitsize,key->params);

    for (int i=0; i<bitsize; i++) {
        bootsSymEncrypt(&ciphertext[i], (plaintext>>i)&1, key);
    }


    //first write to a file so lua script can read encrypted data
    ofstream outfile ("encryptedInteger.txt");
    for(int i=0;i<bitsize;i++)
	{
        for (int j=0; j<500; j++){
            outfile << ciphertext[i].a[j] << endl;

        }
        outfile << ciphertext[i].b << endl;
        outfile << ciphertext[i].current_variance << endl;
	}

    delete_gate_bootstrapping_ciphertext_array(bitsize, ciphertext);    
    delete_gate_bootstrapping_secret_keyset(key);
	return 0;

}

//encrypts given integer part of Double
// ciphertext[0] holds least significant bit
// ciphertext[integerbitsize-1] holds the most significant bit 
LweSample* encryptIntegerpart(int plaintext, TFheGateBootstrappingSecretKeySet* key){
	LweSample *ciphertext = new_gate_bootstrapping_ciphertext_array(integerbitsize,key->params);
	
	for(int i=0;i<integerbitsize;i++)
	{
		bootsSymEncrypt(&ciphertext[i],(plaintext>>i)&0x01,key);
		
	}
	return ciphertext;
}




//when plaintext is given in double type   i.e. 0.xxx
//encrypts given fractional part, where argument plaintext is given as 41 if integer was 124.41
LweSample* encryptFractionpart(double plaintext, TFheGateBootstrappingSecretKeySet* key){

	LweSample *ciphertext = new_gate_bootstrapping_ciphertext_array(fractionbitsize,key->params);
	for(int i=fractionbitsize-1;i>=0;i--)
	{
		plaintext = plaintext * 2;
		if (plaintext >= 1){
			bootsSymEncrypt(&ciphertext[i],1,key);
			
			//get rid of the leading 1
			plaintext = plaintext - 1;
		}
		else {
			bootsSymEncrypt(&ciphertext[i],0,key);
		
		}
	}
	return ciphertext;
}

//given double, encrypts it to Double
Double encryptDouble(double plaintext, TFheGateBootstrappingSecretKeySet* key){
    Double result;

    //fraction part first, then integerpart, from least significant to most significant
    // for instance, 00100101 for -5.75 using 4 bits for decimal and 4 bits for fraction parts
    int bitholder[(integerbitsize + fractionbitsize)];
    double integral;
    int integralint;
    double fractional = modf(plaintext, &integral);
    integralint = integral;
    LweSample *integerpart = new_gate_bootstrapping_ciphertext_array(integerbitsize,key->params);
    LweSample *fractionpart = new_gate_bootstrapping_ciphertext_array(fractionbitsize,key->params);
    //if plaintext is positive 
    if(plaintext >= 0){
        integerpart = encryptIntegerpart(integralint, key);
        fractionpart = encryptFractionpart(fractional, key);
        
    }

    //if plaintext is negative, calculate bits of negative double
    else {
        integralint = (-1) * integralint;
        fractional = (-1) * fractional;
        for(int i=0;i<integerbitsize;i++)
        {
            bitholder[fractionbitsize+i] = (integralint>>i)&0x01;

        }
        for(int i=(fractionbitsize-1);i>=0;i--)
        {
            fractional = fractional * 2;
            if (fractional >= 1){
                bitholder[i] = 1;
                
                //get rid of the leading 1
                fractional = fractional - 1;
            }
            else {
                bitholder[i] = 0;
            }
        }

        //bits of positive representation has been calculated, invert all bits
        for (int i=0; i<(integerbitsize+fractionbitsize);i++){
            if (bitholder[i] == 1){
                bitholder[i] = 0;
            }
            else{
                bitholder[i] = 1;
            }
        }

        //add 1 to the least significant digit
        int carry = 1;
        for (int i=0; i<(integerbitsize+fractionbitsize);i++){
            switch (bitholder[i] + carry){
                case 2:{
                    bitholder[i] = 0;
                    carry = 1;  
                    break;
                }
                case 1:{
                    bitholder[i] = 1;
                    carry = 0;
                    break;
                }
                case 0:{
                    bitholder[i] = 0;
                    carry = 0;
                    break;
                }
            }
        }

        //bitholder now has bits for negative double values, must encrypt
        for(int i=0;i<integerbitsize;i++)
        {
            bootsSymEncrypt(&integerpart[i],bitholder[fractionbitsize+i],key);
            
        }
        for(int i=0;i<fractionbitsize;i++)
        {
            bootsSymEncrypt(&fractionpart[i],bitholder[i],key);
            
        }


    }
    result.integerpart = integerpart;
    result.fractionpart = fractionpart;
    return result;

}

//encrypts given double
static int encryptdouble(lua_State *L){
    double plaintext = luaL_checknumber (L, 1);

    FILE* secret_key = fopen("secret.key","rb");
    key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);

    Double ciphertext = encryptDouble(plaintext, key);

    //first write to a file so lua script can read encrypted data
    ofstream outfile ("encrypteddouble.txt");
    LweSample* integerpart = ciphertext.integerpart;
    LweSample* fractionpart = ciphertext.fractionpart;
    for(int i=0;i<integerbitsize;i++)
	{
        for (int j=0; j<500; j++){
            outfile << integerpart[i].a[j] << endl;
        }
        outfile << integerpart[i].b << endl;
        outfile << integerpart[i].current_variance << endl;
	}
    for(int i=0;i<fractionbitsize;i++)
	{
        for (int j=0; j<500; j++){
            outfile << fractionpart[i].a[j] << endl;

        }
        outfile << fractionpart[i].b << endl;
        outfile << fractionpart[i].current_variance << endl;
	}

    delete_gate_bootstrapping_ciphertext_array(integerbitsize, integerpart);    
    delete_gate_bootstrapping_ciphertext_array(fractionbitsize, fractionpart);
    delete_gate_bootstrapping_secret_keyset(key);
	return 0;

}

//decrypts ciphertext in doubletobedecrypted.txt and returns resulting double
static int decryptdouble(lua_State *L){
    string line;
    int16_t int_answer = 0;
    FILE* secret_key = fopen("secret.key","rb");
    key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);
    const TFheGateBootstrappingParameterSet* params = key->params;

    //read the 16 ciphertexts of the result
    LweSample* integerpart = new_gate_bootstrapping_ciphertext_array(bitsize, params);
    LweSample* fractionpart = new_gate_bootstrapping_ciphertext_array(bitsize, params);

    const int32_t n = params->in_out_params->n;

    for(int i=0; i<32; i++){
        ifstream inputfile ("doubletobedecrypted" + to_string(i)+ ".txt");
        if (is_file_empty(inputfile)){
            delete_gate_bootstrapping_secret_keyset(key);
            delete_gate_bootstrapping_ciphertext_array(bitsize, integerpart);
            delete_gate_bootstrapping_ciphertext_array(bitsize, fractionpart);
            lua_pushnil(L);
            return 1;
        }
    }

    for (int i=0; i<16; i++) {
        ifstream inputfile ("doubletobedecrypted" + to_string(i) + ".txt");
        for (int j=0; j<n; j++){

            getline(inputfile, line);
            integerpart[i].a[j] = stoi(line);
        
        }
        getline(inputfile, line);
        integerpart[i].b = stoi(line);
        getline(inputfile, line);
        integerpart[i].current_variance = stod(line);
        inputfile.close();
    }

    for (int i=16; i<32; i++) {
        ifstream inputfile ("doubletobedecrypted" + to_string(i) + ".txt");
        for (int j=0; j<n; j++){
            getline(inputfile, line);
            fractionpart[i-16].a[j] = stoi(line);
        
        }
        getline(inputfile, line);
        fractionpart[i-16].b = stoi(line);
        getline(inputfile, line);
        fractionpart[i-16].current_variance = stod(line);
        inputfile.close();
    }


    Double thisdouble;
    thisdouble.integerpart = integerpart;
    thisdouble.fractionpart = fractionpart;

    double decrypted = decryptDouble(thisdouble,key);

    
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_ciphertext_array(bitsize, integerpart);
    delete_gate_bootstrapping_ciphertext_array(bitsize, fractionpart);

    lua_pushnumber(L, decrypted);
    return 1;
}

//generates keys in the same folder
static int generatekeys(lua_State *L){
    const int minimum_lambda = 110;
    TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    uint32_t seed[] = { 314, 1592, 657 };
    tfhe_random_generator_setSeed(seed,3);
    TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);

    FILE* secret_key = fopen("secret.key","wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
    fclose(secret_key);

    FILE* cloud_key = fopen("cloud.key","wb");
    export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
    fclose(cloud_key);

    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);
    return 0;
}


static const struct luaL_Reg mylib [] = {
      {"HOMencrypt", encryptinteger},
      {"HOMdecrypt", decryptinteger},
      {"HOMencryptdouble", encryptdouble},
      {"HOMdecryptdouble", decryptdouble},
      {"generatekeys", generatekeys},
      {NULL, NULL}  /* sentinel */
    };

int luaopen_mylib (lua_State *L){
    luaL_register(L, "mylib", mylib);
    return 1;
}


#ifdef __cplusplus
}
#endif