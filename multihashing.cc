#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>

extern "C" {
    #include "bcrypt.h"
    #include "keccak.h"
    #include "quark.h"
    #include "scryptjane.h"
    #include "scryptn.h"
    #include "yescrypt/yescrypt.h"
    #include "yescrypt/sha256_Y.h"
    #include "neoscrypt.h"
    #include "skein.h"
    #include "x11.h"
    #include "groestl.h"
    #include "blake.h"
    #include "fugue.h"
    #include "qubit.h"
    #include "s3.h"
    #include "hefty1.h"
    #include "shavite3.h"
    #include "cryptonight.h"
    #include "x13.h"
    #include "x14.h"
    #include "nist5.h"
    #include "sha1.h"
    #include "x15.h"
    #include "fresh.h"
    #include "dcrypt.h"
    #include "jh.h"
    #include "x5.h"
    #include "c11.h"
}

#include "boolberry.h"

using namespace node;
using namespace v8;

void except(Isolate* isolate, const char* msg) {
    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, msg)));
}

void quark(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() < 1)
        return except(isolate, "You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except(isolate, "Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char * output = (char*) malloc(32);

    uint32_t input_len = Buffer::Length(target);

    quark_hash(input, output, input_len);

    v8::MaybeLocal<v8::Object> buff = Buffer::New(isolate, output, 32);
    args.GetReturnValue().Set(buff.ToLocalChecked());
}

void x11(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() < 1)
        return except(isolate, "You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except(isolate, "Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char * output = (char*) malloc(32);

    uint32_t input_len = Buffer::Length(target);

    x11_hash(input, output, input_len);

    v8::MaybeLocal<v8::Object> buff = Buffer::New(isolate, output, 32);
    args.GetReturnValue().Set(buff.ToLocalChecked());
}

void x5(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() < 1)
        return except(isolate, "You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except(isolate, "Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char * output = (char*) malloc(32);

    uint32_t input_len = Buffer::Length(target);

    x11_hash(input, output, input_len);

    v8::MaybeLocal<v8::Object> buff = Buffer::New(isolate, output, 32);
    args.GetReturnValue().Set(buff.ToLocalChecked());
}

void scrypt(const FunctionCallbackInfo<Value>& args) {
   Isolate* isolate = args.GetIsolate();

   if (args.Length() < 3)
       return except(isolate, "You must provide buffer to hash, N value, and R value");

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target))
       return except(isolate, "Argument should be a buffer object.");

   Local<Number> numn = args[1]->ToNumber();
   unsigned int nValue = numn->Value();
   Local<Number> numr = args[2]->ToNumber();
   unsigned int rValue = numr->Value();

   char * input = Buffer::Data(target);
   char * output = (char*) malloc(32);

   uint32_t input_len = Buffer::Length(target);

   scrypt_N_R_1_256(input, output, nValue, rValue, input_len);

    v8::MaybeLocal<v8::Object> buff = Buffer::New(isolate, output, 32);
    args.GetReturnValue().Set(buff.ToLocalChecked());
}

void neoscrypt_hash(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() < 2)
        return except(isolate, "You must provide two arguments.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except(isolate, "Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char * output = (char*) malloc(32);

    uint32_t input_len = Buffer::Length(target);

    neoscrypt(input, output, 0);

    v8::MaybeLocal<v8::Object> buff = Buffer::New(isolate, output, 32);
    args.GetReturnValue().Set(buff.ToLocalChecked());
}


void scryptn(const FunctionCallbackInfo<Value>& args) {
   Isolate* isolate = args.GetIsolate();

   if (args.Length() < 2)
       return except(isolate, "You must provide buffer to hash and N factor.");

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target))
       return except(isolate, "Argument should be a buffer object.");

   Local<Number> num = args[1]->ToNumber();
   unsigned int nFactor = num->Value();

   char * input = Buffer::Data(target);
   char * output = (char*) malloc(32);

   uint32_t input_len = Buffer::Length(target);

   //unsigned int N = 1 << (getNfactor(input) + 1);
   unsigned int N = 1 << nFactor;

   scrypt_N_R_1_256(input, output, N, 1, input_len); //hardcode for now to R=1 for now


    v8::MaybeLocal<v8::Object> buff = Buffer::New(isolate, output, 32);
    args.GetReturnValue().Set(buff.ToLocalChecked());
}

void scryptjane(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() < 5)
        return except(isolate, "You must provide two argument: buffer, timestamp as number, and nChainStarTime as number, nMin, and nMax");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except(isolate, "First should be a buffer object.");

    Local<Number> num = args[1]->ToNumber();
    int timestamp = num->Value();

    Local<Number> num2 = args[2]->ToNumber();
    int nChainStartTime = num2->Value();

    Local<Number> num3 = args[3]->ToNumber();
    int nMin = num3->Value();

    Local<Number> num4 = args[4]->ToNumber();
    int nMax = num4->Value();

    char * input = Buffer::Data(target);
    char * output = (char*) malloc(32);

    uint32_t input_len = Buffer::Length(target);

    scryptjane_hash(input, input_len, (uint32_t *)output, GetNfactorJane(timestamp, nChainStartTime, nMin, nMax));

    v8::MaybeLocal<v8::Object> buff = Buffer::New(isolate, output, 32);
    args.GetReturnValue().Set(buff.ToLocalChecked());
}

void yescrypt(const FunctionCallbackInfo<Value>& args) {
   Isolate* isolate = args.GetIsolate();

    if (args.Length() < 1)
        return except(isolate, "You must provide one argument.");

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target))
       return except(isolate, "Argument should be a buffer object.");

   char * input = Buffer::Data(target);
   char * output = (char*) malloc(32);

   yescrypt_hash(input, output);

    v8::MaybeLocal<v8::Object> buff = Buffer::New(isolate, output, 32);
    args.GetReturnValue().Set(buff.ToLocalChecked());
}

void keccak(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() < 1)
        return except(isolate, "You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except(isolate, "Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char * output = (char*) malloc(32);

    unsigned int dSize = Buffer::Length(target);

    keccak_hash(input, output, dSize);

    v8::MaybeLocal<v8::Object> buff = Buffer::New(isolate, output, 32);
    args.GetReturnValue().Set(buff.ToLocalChecked());
}


void bcrypt(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() < 1)
        return except(isolate, "You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except(isolate, "Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char * output = (char*) malloc(32);

    bcrypt_hash(input, output);

    v8::MaybeLocal<v8::Object> buff = Buffer::New(isolate, output, 32);
    args.GetReturnValue().Set(buff.ToLocalChecked());
}

void skein(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() < 1)
        return except(isolate, "You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except(isolate, "Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char * output = (char*) malloc(32);

    uint32_t input_len = Buffer::Length(target);

    skein_hash(input, output, input_len);

    v8::MaybeLocal<v8::Object> buff = Buffer::New(isolate, output, 32);
    args.GetReturnValue().Set(buff.ToLocalChecked());
}


void groestl(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() < 1)
        return except(isolate, "You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except(isolate, "Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char * output = (char*) malloc(32);

    uint32_t input_len = Buffer::Length(target);

    groestl_hash(input, output, input_len);

    v8::MaybeLocal<v8::Object> buff = Buffer::New(isolate, output, 32);
    args.GetReturnValue().Set(buff.ToLocalChecked());
}


void groestlmyriad(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() < 1)
        return except(isolate, "You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except(isolate, "Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char * output = (char*) malloc(32);

    uint32_t input_len = Buffer::Length(target);

    groestlmyriad_hash(input, output, input_len);

    v8::MaybeLocal<v8::Object> buff = Buffer::New(isolate, output, 32);
    args.GetReturnValue().Set(buff.ToLocalChecked());
}


void blake(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() < 1)
        return except(isolate, "You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except(isolate, "Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char * output = (char*) malloc(32);

    uint32_t input_len = Buffer::Length(target);

    blake_hash(input, output, input_len);

    v8::MaybeLocal<v8::Object> buff = Buffer::New(isolate, output, 32);
    args.GetReturnValue().Set(buff.ToLocalChecked());
}

void dcrypt(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() < 1)
        return except(isolate, "You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except(isolate, "Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char * output = (char*) malloc(32);

    uint32_t input_len = Buffer::Length(target);

    dcrypt_hash(input, output, input_len);

    v8::MaybeLocal<v8::Object> buff = Buffer::New(isolate, output, 32);
    args.GetReturnValue().Set(buff.ToLocalChecked());
}

void fugue(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() < 1)
        return except(isolate, "You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except(isolate, "Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char * output = (char*) malloc(32);

    uint32_t input_len = Buffer::Length(target);

    fugue_hash(input, output, input_len);

    v8::MaybeLocal<v8::Object> buff = Buffer::New(isolate, output, 32);
    args.GetReturnValue().Set(buff.ToLocalChecked());
}


void qubit(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() < 1)
        return except(isolate, "You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except(isolate, "Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char * output = (char*) malloc(32);

    uint32_t input_len = Buffer::Length(target);

    qubit_hash(input, output, input_len);

    v8::MaybeLocal<v8::Object> buff = Buffer::New(isolate, output, 32);
    args.GetReturnValue().Set(buff.ToLocalChecked());
}

void s3(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() < 1)
        return except(isolate, "You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except(isolate, "Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char * output = (char*) malloc(32);

    uint32_t input_len = Buffer::Length(target);

    s3_hash(input, output, input_len);

    v8::MaybeLocal<v8::Object> buff = Buffer::New(isolate, output, 32);
    args.GetReturnValue().Set(buff.ToLocalChecked());
}

void hefty1(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() < 1)
        return except(isolate, "You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except(isolate, "Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char * output = (char*) malloc(32);

    uint32_t input_len = Buffer::Length(target);

    hefty1_hash(input, output, input_len);

    v8::MaybeLocal<v8::Object> buff = Buffer::New(isolate, output, 32);
    args.GetReturnValue().Set(buff.ToLocalChecked());
}


void shavite3(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() < 1)
        return except(isolate, "You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except(isolate, "Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char * output = (char*) malloc(32);

    uint32_t input_len = Buffer::Length(target);

    shavite3_hash(input, output, input_len);

    v8::MaybeLocal<v8::Object> buff = Buffer::New(isolate, output, 32);
    args.GetReturnValue().Set(buff.ToLocalChecked());
}

void cryptonight(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    bool fast = false;

    if (args.Length() < 1)
        return except(isolate, "You must provide one argument.");

    if (args.Length() >= 2) {
        if(!args[1]->IsBoolean())
            return except(isolate, "Argument 2 should be a boolean");
        fast = args[1]->ToBoolean()->BooleanValue();
    }

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except(isolate, "Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char * output = (char*) malloc(32);

    uint32_t input_len = Buffer::Length(target);

    if(fast)
        cryptonight_fast_hash(input, output, input_len);
    else
        cryptonight_hash(input, output, input_len);

    v8::MaybeLocal<v8::Object> buff = Buffer::New(isolate, output, 32);
    args.GetReturnValue().Set(buff.ToLocalChecked());
}

void x13(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() < 1)
        return except(isolate, "You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except(isolate, "Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char * output = (char*) malloc(32);

    uint32_t input_len = Buffer::Length(target);

    x13_hash(input, output, input_len);

    v8::MaybeLocal<v8::Object> buff = Buffer::New(isolate, output, 32);
    args.GetReturnValue().Set(buff.ToLocalChecked());
}

void x14(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() < 1)
        return except(isolate, "You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except(isolate, "Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char * output = (char*) malloc(32);

    uint32_t input_len = Buffer::Length(target);

    x14_hash(input, output, input_len);

    v8::MaybeLocal<v8::Object> buff = Buffer::New(isolate, output, 32);
    args.GetReturnValue().Set(buff.ToLocalChecked());
}

void boolberry(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() < 2)
        return except(isolate, "You must provide two arguments.");

    Local<Object> target = args[0]->ToObject();
    Local<Object> target_spad = args[1]->ToObject();
    uint32_t height = 1;

    if(!Buffer::HasInstance(target))
        return except(isolate, "Argument 1 should be a buffer object.");

    if(!Buffer::HasInstance(target_spad))
        return except(isolate, "Argument 2 should be a buffer object.");

    if(args.Length() >= 3)
        if(args[2]->IsUint32())
            height = args[2]->ToUint32()->Uint32Value();
        else
            return except(isolate, "Argument 3 should be an unsigned integer.");

    char * input = Buffer::Data(target);
    char * scratchpad = Buffer::Data(target_spad);
    char * output = (char*) malloc(32);

    uint32_t input_len = Buffer::Length(target);
    uint64_t spad_len = Buffer::Length(target_spad);

    boolberry_hash(input, input_len, scratchpad, spad_len, output, height);

    v8::MaybeLocal<v8::Object> buff = Buffer::New(isolate, output, 32);
    args.GetReturnValue().Set(buff.ToLocalChecked());
}

void nist5(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() < 1)
        return except(isolate, "You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except(isolate, "Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char * output = (char*) malloc(32);

    uint32_t input_len = Buffer::Length(target);

    nist5_hash(input, output, input_len);

    v8::MaybeLocal<v8::Object> buff = Buffer::New(isolate, output, 32);
    args.GetReturnValue().Set(buff.ToLocalChecked());
}

void sha1(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() < 1)
        return except(isolate, "You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except(isolate, "Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char * output = (char*) malloc(32);

    uint32_t input_len = Buffer::Length(target);

    sha1_hash(input, output, input_len);

    v8::MaybeLocal<v8::Object> buff = Buffer::New(isolate, output, 32);
    args.GetReturnValue().Set(buff.ToLocalChecked());
}

void x15(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() < 1)
        return except(isolate, "You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except(isolate, "Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char * output = (char*) malloc(32);

    uint32_t input_len = Buffer::Length(target);

    x15_hash(input, output, input_len);

    v8::MaybeLocal<v8::Object> buff = Buffer::New(isolate, output, 32);
    args.GetReturnValue().Set(buff.ToLocalChecked());
}

void fresh(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() < 1)
        return except(isolate, "You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except(isolate, "Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char * output = (char*) malloc(32);

    uint32_t input_len = Buffer::Length(target);

    fresh_hash(input, output, input_len);

    v8::MaybeLocal<v8::Object> buff = Buffer::New(isolate, output, 32);
    args.GetReturnValue().Set(buff.ToLocalChecked());
}

void jh(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() < 1)
        return except(isolate, "You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except(isolate, "Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char * output = (char*) malloc(32);

    uint32_t input_len = Buffer::Length(target);

    jh_hash(input, output, input_len);

    v8::MaybeLocal<v8::Object> buff = Buffer::New(isolate, output, 32);
    args.GetReturnValue().Set(buff.ToLocalChecked());
}

void c11(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() < 1)
        return except(isolate, "You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except(isolate, "Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char * output = (char*) malloc(32);

    uint32_t input_len = Buffer::Length(target);

    c11_hash(input, output);

    v8::MaybeLocal<v8::Object> buff = Buffer::New(isolate, output, 32);
    args.GetReturnValue().Set(buff.ToLocalChecked());
}

void init(Local<Object> exports) {
    NODE_SET_METHOD(exports, "quark", quark);
    NODE_SET_METHOD(exports, "x11", x11);
    NODE_SET_METHOD(exports, "scrypt", scrypt);
    NODE_SET_METHOD(exports, "scryptn", scryptn);
    NODE_SET_METHOD(exports, "scryptjane", scryptjane);
    NODE_SET_METHOD(exports, "yescrypt", yescrypt);
    NODE_SET_METHOD(exports, "keccak", keccak);
    NODE_SET_METHOD(exports, "bcrypt", bcrypt);
    NODE_SET_METHOD(exports, "skein", skein);
    NODE_SET_METHOD(exports, "groestl", groestl);
    NODE_SET_METHOD(exports, "groestlmyriad", groestlmyriad);
    NODE_SET_METHOD(exports, "blake", blake);
    NODE_SET_METHOD(exports, "fugue", fugue);
    NODE_SET_METHOD(exports, "qubit", qubit);
    NODE_SET_METHOD(exports, "hefty1", hefty1);
    NODE_SET_METHOD(exports, "shavite3", shavite3);
    NODE_SET_METHOD(exports, "cryptonight", cryptonight);
    NODE_SET_METHOD(exports, "x13", x13);
    NODE_SET_METHOD(exports, "x14", x14);
    NODE_SET_METHOD(exports, "boolberry", boolberry);
    NODE_SET_METHOD(exports, "nist5", nist5);
    NODE_SET_METHOD(exports, "sha1", sha1);
    NODE_SET_METHOD(exports, "x15", x15);
    NODE_SET_METHOD(exports, "fresh", fresh);
    NODE_SET_METHOD(exports, "s3", s3);
    NODE_SET_METHOD(exports, "neoscrypt", neoscrypt_hash);
    NODE_SET_METHOD(exports, "dcrypt", dcrypt);
    NODE_SET_METHOD(exports, "jh", jh);
    NODE_SET_METHOD(exports, "c11", c11);
}

NODE_MODULE(multihashing, init)
