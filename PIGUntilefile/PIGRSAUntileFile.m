//
//  PIGRSAUntileFile.m
//  IOSDemo
//
//  Created by CCBLifeCarblet on 2019/3/4.
//  Copyright © 2019年 CCBLifeCarblet. All rights reserved.
//

#import "PIGRSAUntileFile.h"
#import <Security/Security.h>
#import "NSObject+PIGCategory.h"
@implementation PIGRSAUntileFile

#pragma ------------------ 公钥 加密 -----------------------------
+ (NSString *)EncryptString:(NSString *)context publicWithContextFile:(NSString *)path
{
    if (!context||!path) return nil;
    
   SecKeyRef keyRef = [self getPublicKeyRefWithContentsOfFile:path];
    
   NSData * data = [self encryptData:[context dataUsingEncoding:NSUTF8StringEncoding] withKeyRef:keyRef];
   
    return base64_encode_data(data);
}



//公钥 加密
+(NSString*)EncryptString:(NSString *)context publicKey:(NSString *)key{
    
    NSData * data = [self encryptData:[context dataUsingEncoding:NSUTF8StringEncoding] publicKey:key];
    NSString * res = base64_encode_data(data);
    return res;
}

+ (NSData *)encryptData:(NSData *)data publicKey:(NSString *)pubKey{
    if(!data || !pubKey){
        return nil;
    }
    SecKeyRef keyRef = [self GetpublicKey:pubKey];
    if(!keyRef){
        return nil;
    }
    return [self encryptData:data withKeyRef:keyRef];
}


#pragma ---------------  核心 部分 ------------------------------------

//获取公钥
+ (SecKeyRef)getPublicKeyRefWithContentsOfFile:(NSString *)filePath{
    NSData *certData = [NSData dataWithContentsOfFile:filePath];
    if (!certData) {
        return nil;
    }
    SecCertificateRef cert = SecCertificateCreateWithData(NULL, (CFDataRef)certData);
    SecKeyRef key = NULL;
    SecTrustRef trust = NULL;
    SecPolicyRef policy = NULL;
    if (cert != NULL) {
        policy = SecPolicyCreateBasicX509();
        if (policy) {
            if (SecTrustCreateWithCertificates((CFTypeRef)cert, policy, &trust) == noErr) {
                SecTrustResultType result;
                if (SecTrustEvaluate(trust, &result) == noErr) {
                    key = SecTrustCopyPublicKey(trust);
                }
            }
        }
    }
    if (policy) CFRelease(policy);
    if (trust) CFRelease(trust);
    if (cert) CFRelease(cert);
    return key;
}



+(SecKeyRef)GetpublicKey:(NSString*)key{
    
    NSRange spos = [key rangeOfString:@"-----BEGIN PUBLIC KEY-----"];
    
    NSRange epos = [key rangeOfString:@"-----END PUBLIC KEY-----"];
    
    if (spos.location != NSNotFound && epos.location != NSNotFound) {
        
        NSUInteger s = spos.location+spos.length;
        
        NSUInteger l = epos.location;
        
        key = [key substringWithRange:NSMakeRange(s, l-s)];
    }
    
    //处理 特殊
    key = [key stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@" "  withString:@""];

    NSData * data = base64_decode(key);
    data = [self publicKeyHeader:data];
    if (!data) {
        return nil;
    }
    
    
    // This will be base64 encoded, decode it
    NSString * tag = @"RSAUtil_PubKey";
    
    NSData * data_tag = [NSData dataWithBytes:[tag UTF8String] length:tag.length];
    
    // Delete any old lingering key with the same tag
    NSMutableDictionary * pubkey = [[NSMutableDictionary alloc]init];
    
    [pubkey setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    
    [pubkey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    [pubkey setObject:data_tag forKey: (__bridge id)kSecAttrApplicationTag];
    
    SecItemDelete((__bridge CFDictionaryRef) pubkey);
    
    // Add persistent version of the key to system keychain
    [pubkey setObject:data forKey:(__bridge id)kSecValueData];
    
    [pubkey setObject:(__bridge id) kSecAttrKeyClassPublic forKey:(__bridge id)
     kSecAttrKeyClass];
    
    [pubkey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)
     kSecReturnPersistentRef];
    
    CFTypeRef persistKey = nil;
    
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)pubkey, &persistKey);
    
    if (persistKey != nil){
        CFRelease(persistKey);
    }
    if ((status != noErr) && (status != errSecDuplicateItem)) {
        return nil;
    }
    
    [pubkey removeObjectForKey:(__bridge id)kSecValueData];
    [pubkey removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [pubkey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    [pubkey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    // Now fetch the SecKeyRef version of the key
    SecKeyRef keyRef = nil;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)pubkey, (CFTypeRef *)&keyRef);
    if(status != noErr){
        return nil;
    }
    return keyRef;

    
}

+(NSData*)publicKeyHeader:(NSData*)data_key{
    
    if (data_key==nil) return nil;
    
    unsigned long len = data_key.length;
    
    if (!len) return nil;
    
    unsigned char * c_key = (unsigned char *)data_key.bytes;
    
    unsigned int indext = 0;
    
    if (c_key[indext++] != 0x30) return nil;
    
    if (c_key[indext] > 0x80) indext += c_key[indext] - 0x80 + 1;
    
    else indext++;
    
    static unsigned char seqiod[] = { 0x30,   0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x01, 0x05, 0x00 };
    
    // 比较前 15 个 字节
    if (memcmp(&c_key[indext], seqiod, 15)) return nil;
    
    indext+=15;
    
    if (c_key[indext++] != 0x30) return nil;
    
    if (c_key[indext] > 0x80)  indext += c_key[indext] - 0x80 +1;
    
    else indext++;
    
    if (c_key[indext++] != '\0') return nil;
    
    return [NSData dataWithBytes:&c_key[indext] length:len - indext];
}


// 加密 操作
+(NSData*)encryptData:(NSData *)data withKeyRef:(SecKeyRef) keyRef{
    
    const uint8_t * srcbuf = (const uint8_t*) data.bytes;
    
    size_t srclen = (size_t) data.length;
    
    size_t block_size = SecKeyGetBlockSize(keyRef);
    
    void *outBuf = malloc(block_size);
    
    size_t src_block_size = block_size - 11;
    
    NSMutableData * ret = [[NSMutableData alloc]init];
    
    for (int idx = 0; idx < srclen; idx +=src_block_size) {
        
        size_t data_len = srclen - idx;
        
        if (data_len > src_block_size) {
            data_len = src_block_size;
        }
        size_t outlen = block_size;
        
        // 整个 加密
        OSStatus status = noErr;
        
        status = SecKeyEncrypt(keyRef,
                               kSecPaddingPKCS1,
                               srcbuf + idx,
                               data_len,
                               outBuf,
                               &outlen);
        
        if (status != 0) {
            ret = nil;
            break;
        }else{
            
            [ret appendBytes:outBuf length:outlen];
        }
        
    }
    free(outBuf);
    
    CFRelease(keyRef);
    
    return ret;
    
}




#pragma   ----------------------- 私钥 解密 -------------------------

+ (NSString *)DecryptString:(NSString *)context privateWithContextFile:(NSString *)path password:(NSString *)password

{
    if (!context||!path||!password) {
        return nil;
    }
    
    SecKeyRef keyRef = [self getPrivateKeyRefWithContentsOfFile:path password:password];
    
    if (!keyRef) return nil;
    
    NSData * data = base64_decode(context);
    
    data =  [self DecryptData:data withKeyRef:keyRef];
    
    NSString * ret = [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding];
    
    return ret;
}

//使用私钥解密
+ (NSString *)DecryptString:(NSString *)context privateKey:(NSString *)key{
    if (!context) {
        return nil;
    }
    NSData * data = base64_decode(context);
    
    data = [self DecryptData:data privateKey:key];
    
    NSString * ret = [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding];
    
    return ret;
}

+(NSData*)DecryptData:(NSData*)data privateKey:(NSString*)privateKey{
    
    if (!data||!privateKey) {
        return nil;
    }
    
    SecKeyRef keyRef = [self GetpublicKey:privateKey];
    
    if (!keyRef) {
        return nil;
    }
    return [self DecryptData:data withKeyRef:keyRef];
}



#pragma --------------   核心 部分 ------------------------------


//获取私钥
+ (SecKeyRef)getPrivateKeyRefWithContentsOfFile:(NSString *)filePath password:(NSString*)password{
    
    NSData *p12Data = [NSData dataWithContentsOfFile:filePath];
    if (!p12Data) {
        return nil;
    }
    SecKeyRef privateKeyRef = NULL;
    NSMutableDictionary * options = [[NSMutableDictionary alloc] init];
    [options setObject: password forKey:(__bridge id)kSecImportExportPassphrase];
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    OSStatus securityError = SecPKCS12Import((__bridge CFDataRef) p12Data, (__bridge CFDictionaryRef)options, &items);
    if (securityError == noErr && CFArrayGetCount(items) > 0) {
        CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 0);
        SecIdentityRef identityApp = (SecIdentityRef)CFDictionaryGetValue(identityDict, kSecImportItemIdentity);
        securityError = SecIdentityCopyPrivateKey(identityApp, &privateKeyRef);
        if (securityError != noErr) {
            privateKeyRef = NULL;
        }
    }
    CFRelease(items);
    
    return privateKeyRef;
}



//私有的Key
+(SecKeyRef)GetprivateKey:(NSString*)privateKey{
    
    NSRange spos = [privateKey rangeOfString:@"-----BEGIN RSA PRIVATE KEY-----"];
    
    NSRange epos = [privateKey rangeOfString:@"-----END RSA PRIVATE KEY-----"];
    
    if (spos.location != NSNotFound && epos.location != NSNotFound) {
        
        NSUInteger s = spos.location+spos.length;
        
        NSUInteger l = epos.location;
        
        privateKey = [privateKey substringWithRange:NSMakeRange(s, l-s)];
    }
    
    //处理 特殊
    privateKey = [privateKey stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    privateKey = [privateKey stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    privateKey = [privateKey stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    privateKey = [privateKey stringByReplacingOccurrencesOfString:@" "  withString:@""];
    
    NSData * data = base64_decode(privateKey);
    data = [self privateKeyHeader:data];
    if (!data) {
        return nil;
    }
    
    
    // This will be base64 encoded, decode it
    NSString * tag = @"RSAUtil_PrivateKey";
    
    NSData * data_tag = [NSData dataWithBytes:[tag UTF8String] length:tag.length];
    
    // Delete any old lingering key with the same tag
    NSMutableDictionary * key = [[NSMutableDictionary alloc]init];
    
    [key setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    
    [key setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    [key setObject:data_tag forKey: (__bridge id)kSecAttrApplicationTag];
    
    SecItemDelete((__bridge CFDictionaryRef) key);
    
    // Add persistent version of the key to system keychain
    [key setObject:data forKey:(__bridge id)kSecValueData];
    [key setObject:(__bridge id) kSecAttrKeyClassPublic forKey:(__bridge id)
     kSecAttrKeyClass];
    [key setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)
     kSecReturnPersistentRef];
    
    CFTypeRef persistKey = nil;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)key, &persistKey);
    if (persistKey != nil){
        CFRelease(persistKey);
    }
    if ((status != noErr) && (status != errSecDuplicateItem)) {
        return nil;
    }
    
    [key removeObjectForKey:(__bridge id)kSecValueData];
    [key removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [key setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    [key setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    // Now fetch the SecKeyRef version of the key
    SecKeyRef keyRef = nil;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)key, (CFTypeRef *)&keyRef);
    if(status != noErr){
        return nil;
    }
    return keyRef;
}


+(NSData*)privateKeyHeader:(NSData*)privateKey
{
    if (privateKey == nil) return (nil);
    
    unsigned long len = privateKey.length;
    
    if (!len) return nil;
    
    unsigned char * c_key = (unsigned char *) privateKey.bytes;
    
    unsigned int idx = 22;
    
    if (0x04 != c_key[idx++]) return nil;
    
    unsigned int c_len = c_key[idx++];
    
    int det = c_len & 0x80;
    
    if (!det) {
       
        c_len = c_len & 0x7f;
        
    }else{
        int byteCount = c_len & 0x7f;
        
        if (byteCount + idx > len) {
            return  nil;
        }
        
        unsigned int accum = 0;
        
        unsigned char * ptr = &c_key[idx];
        
        idx += byteCount;
        
        while (byteCount) {
            
            accum = (accum << 8) + * ptr;
            
            ptr ++ ;
            
            byteCount -- ;
        }
        
        c_len = accum;
    }
    
    //
    return [privateKey subdataWithRange:NSMakeRange(idx, c_len)];
}

+(NSData*)DecryptData:(NSData*)data withKeyRef:(SecKeyRef)keyRef
{
    const uint8_t *srcbuf = (const uint8_t *)[data bytes];
    size_t srclen = (size_t)data.length;
    
    size_t block_size = SecKeyGetBlockSize(keyRef) * sizeof(uint8_t);
    UInt8 *outbuf = malloc(block_size);
    size_t src_block_size = block_size;
    
    NSMutableData *ret = [[NSMutableData alloc] init];
    for(int idx=0; idx<srclen; idx+=src_block_size){
        //NSLog(@"%d/%d block_size: %d", idx, (int)srclen, (int)block_size);
        size_t data_len = srclen - idx;
        if(data_len > src_block_size){
            data_len = src_block_size;
        }
        
        size_t outlen = block_size;
        OSStatus status = noErr;
        status = SecKeyDecrypt(keyRef,
                               kSecPaddingNone,
                               srcbuf + idx,
                               data_len,
                               outbuf,
                               &outlen
                               );
        if (status != 0) {
            NSLog(@"SecKeyEncrypt fail. Error Code: %d", status);
            ret = nil;
            break;
        }else{
            //the actual decrypted data is in the middle, locate it!
            int idxFirstZero = -1;
            int idxNextZero = (int)outlen;
            for ( int i = 0; i < outlen; i++ ) {
                if ( outbuf[i] == 0 ) {
                    if ( idxFirstZero < 0 ) {
                        idxFirstZero = i;
                    } else {
                        idxNextZero = i;
                        break;
                    }
                }
            }
            
            [ret appendBytes:&outbuf[idxFirstZero+1] length:idxNextZero-idxFirstZero-1];
        }
    }
    
    free(outbuf);
    CFRelease(keyRef);
    return ret;
}


@end
