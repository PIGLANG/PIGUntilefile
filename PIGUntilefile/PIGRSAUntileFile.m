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


#pragma --------------------  公钥 ------------------------

+ (NSData *)PublicKeyHeader:(NSData *)d_key{
    if (d_key == nil) return(nil);
    
    unsigned long len = [d_key length];
    if (!len) return(nil);
    
    unsigned char *c_key = (unsigned char *)[d_key bytes];
    unsigned int  idx     = 0;
    
    if (c_key[idx++] != 0x30) return(nil);
    
    if (c_key[idx] > 0x80) idx += c_key[idx] - 0x80 + 1;
    else idx++;
    
    static unsigned char seqiod[] =
    { 0x30,   0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x01, 0x05, 0x00 };
    if (memcmp(&c_key[idx], seqiod, 15)) return(nil);
    
    idx += 15;
    
    if (c_key[idx++] != 0x03) return(nil);
    
    if (c_key[idx] > 0x80) idx += c_key[idx] - 0x80 + 1;
    else idx++;
    
    if (c_key[idx++] != '\0') return(nil);
    return([NSData dataWithBytes:&c_key[idx] length:len - idx]);
}

+ (SecKeyRef)GetPublicKey:(NSString *)key{
    NSRange spos = [key rangeOfString:@"-----BEGIN PUBLIC KEY-----"];
    NSRange epos = [key rangeOfString:@"-----END PUBLIC KEY-----"];
    if(spos.location != NSNotFound && epos.location != NSNotFound){
        NSUInteger s = spos.location + spos.length;
        NSUInteger e = epos.location;
        NSRange range = NSMakeRange(s, e-s);
        key = [key substringWithRange:range];
    }
    key = [key stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@" "  withString:@""];
    
    NSData *data = PIGbase64_decode(key);
    data = [self PublicKeyHeader:data];
    if(!data){
        return nil;
    }
    
    NSString *tag = @"RSAUtil_PubKey";
    NSData *d_tag = [NSData dataWithBytes:[tag UTF8String] length:[tag length]];
    
    // Delete any old lingering key with the same tag
    NSMutableDictionary *publicKey = [[NSMutableDictionary alloc] init];
    [publicKey setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    [publicKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [publicKey setObject:d_tag forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)publicKey);
    
    // Add persistent version of the key to system keychain
    [publicKey setObject:data forKey:(__bridge id)kSecValueData];
    [publicKey setObject:(__bridge id) kSecAttrKeyClassPublic forKey:(__bridge id)
     kSecAttrKeyClass];
    [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)
     kSecReturnPersistentRef];
    
    CFTypeRef persistKey = nil;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)publicKey, &persistKey);
    if (persistKey != nil){
        CFRelease(persistKey);
    }
    if ((status != noErr) && (status != errSecDuplicateItem)) {
        return nil;
    }
    
    [publicKey removeObjectForKey:(__bridge id)kSecValueData];
    [publicKey removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    [publicKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    // Now fetch the SecKeyRef version of the key
    SecKeyRef keyRef = nil;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)publicKey, (CFTypeRef *)&keyRef);
    if(status != noErr){
        return nil;
    }
    return keyRef;
}

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









#pragma  ----------------------   私钥 --------------------------

#pragma PrivateKeyHeader
+ (NSData *)PrivateKeyHeader:(NSData *)d_key{
    if (d_key == nil) return(nil);
    
    unsigned long len = [d_key length];
    if (!len) return(nil);
    
    unsigned char *c_key = (unsigned char *)[d_key bytes];
    unsigned int  idx     = 22;
    
    if (0x04 != c_key[idx++]) return nil;
    unsigned int c_len = c_key[idx++];
    int det = c_len & 0x80;
    if (!det) {
        c_len = c_len & 0x7f;
    } else {
        int byteCount = c_len & 0x7f;
        if (byteCount + idx > len) {
            return nil;
        }
        unsigned int accum = 0;
        unsigned char *ptr = &c_key[idx];
        idx += byteCount;
        while (byteCount) {
            accum = (accum << 8) + *ptr;
            ptr++;
            byteCount--;
        }
        c_len = accum;
    }
    return [d_key subdataWithRange:NSMakeRange(idx, c_len)];
}

#pragma  SecKeyRef
+ (SecKeyRef)GetPrivateKey:(NSString *)key{
    NSRange spos;
    NSRange epos;
    spos = [key rangeOfString:@"-----BEGIN RSA PRIVATE KEY-----"];
    if(spos.length > 0){
        epos = [key rangeOfString:@"-----END RSA PRIVATE KEY-----"];
    }else{
        spos = [key rangeOfString:@"-----BEGIN PRIVATE KEY-----"];
        epos = [key rangeOfString:@"-----END PRIVATE KEY-----"];
    }
    if(spos.location != NSNotFound && epos.location != NSNotFound){
        NSUInteger s = spos.location + spos.length;
        NSUInteger e = epos.location;
        NSRange range = NSMakeRange(s, e-s);
        key = [key substringWithRange:range];
    }
    key = [key stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@" "  withString:@""];
    
    // This will be base64 encoded, decode it.
    NSData *data = PIGbase64_decode(key);
    data = [self PrivateKeyHeader:data];
    if(!data){
        return nil;
    }
    
    //a tag to read/write keychain storage
    NSString *tag = @"RSAUtil_PrivKey";
    NSData *d_tag = [NSData dataWithBytes:[tag UTF8String] length:[tag length]];
    
    // Delete any old lingering key with the same tag
    NSMutableDictionary *privateKey = [[NSMutableDictionary alloc] init];
    [privateKey setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    [privateKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [privateKey setObject:d_tag forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)privateKey);
    
    // Add persistent version of the key to system keychain
    [privateKey setObject:data forKey:(__bridge id)kSecValueData];
    [privateKey setObject:(__bridge id) kSecAttrKeyClassPrivate forKey:(__bridge id)
     kSecAttrKeyClass];
    [privateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)
     kSecReturnPersistentRef];
    
    CFTypeRef persistKey = nil;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)privateKey, &persistKey);
    if (persistKey != nil){
        CFRelease(persistKey);
    }
    if ((status != noErr) && (status != errSecDuplicateItem)) {
        return nil;
    }
    
    [privateKey removeObjectForKey:(__bridge id)kSecValueData];
    [privateKey removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [privateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    [privateKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    // Now fetch the SecKeyRef version of the key
    SecKeyRef keyRef = nil;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)privateKey, (CFTypeRef *)&keyRef);
    if(status != noErr){
        return nil;
    }
    return keyRef;
}



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


#pragma   ---------------------------- 加密 核心-----------------------

+ (NSData *)encryptData:(NSData *)data withKeyRef:(SecKeyRef) keyRef isSign:(BOOL)isSign {
    const uint8_t *srcbuf = (const uint8_t *)[data bytes];
    size_t srclen = (size_t)data.length;
    
    size_t block_size = SecKeyGetBlockSize(keyRef) * sizeof(uint8_t);
    void *outbuf = malloc(block_size);
    size_t src_block_size = block_size - 11;
    
    NSMutableData *ret = [[NSMutableData alloc] init];
    for(int idx=0; idx<srclen; idx+=src_block_size){
        //NSLog(@"%d/%d block_size: %d", idx, (int)srclen, (int)block_size);
        size_t data_len = srclen - idx;
        if(data_len > src_block_size){
            data_len = src_block_size;
        }
        
        size_t outlen = block_size;
        OSStatus status = noErr;
        
        if (isSign) {
            status = SecKeyRawSign(keyRef,
                                   kSecPaddingPKCS1,
                                   srcbuf + idx,
                                   data_len,
                                   outbuf,
                                   &outlen
                                   );
        } else {
            status = SecKeyEncrypt(keyRef,
                                   kSecPaddingPKCS1,
                                   srcbuf + idx,
                                   data_len,
                                   outbuf,
                                   &outlen
                                   );
        }
        if (status != 0) {
            NSLog(@"SecKeyEncrypt fail. Error Code: %d", status);
            ret = nil;
            break;
        }else{
            [ret appendBytes:outbuf length:outlen];
        }
    }
    
    free(outbuf);
    CFRelease(keyRef);
    return ret;
}



+ (NSData *)decryptData:(NSData *)data withKeyRef:(SecKeyRef) keyRef{
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





#pragma --------------------  对外接口 ------------------

#pragma 私钥处理

/**
 * 私钥加密
 * @param context 加密内容
 * @param privateKey 私钥
 */
+(NSString *)EncryptString:(NSString *)context privateKey:(NSString *)privateKey{
    NSData *data = [self EncryptData:[context dataUsingEncoding:NSUTF8StringEncoding] privateKey:privateKey];
    NSString *ret = PIGbase64_encode_data(data);
    return ret;
    
}

/**
 * 私钥加密
 * @param contextData 加密内容
 * @param privateKey 私钥
 */
+ (NSData *)EncryptData:(NSData *)contextData privateKey:(NSString *)privateKey{
    if(!contextData || !privateKey){
        return nil;
    }
    SecKeyRef keyRef = [self GetPrivateKey:privateKey];
    if(!keyRef){
        return nil;
    }
    return [self encryptData:contextData withKeyRef:keyRef isSign:YES];
}


/**
 * 私钥解密
 *
 */

+ (NSString *)DecryptString:(NSString *)str privateKey:(NSString *)privateKey{
    NSData *data = [[NSData alloc] initWithBase64EncodedString:str options:NSDataBase64DecodingIgnoreUnknownCharacters];
    data = [self DecryptData:data privateKey:privateKey];
    NSString *ret = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return ret;
}
/**
 * 私钥解密
 *
 */
+ (NSData *)DecryptData:(NSData *)contextData privateKey:(NSString *)privateKey{
    if(!contextData || !privateKey){
        return nil;
    }
    SecKeyRef keyRef = [self GetPrivateKey:privateKey];
    if(!keyRef){
        return nil;
    }
    return [self decryptData:contextData withKeyRef:keyRef];
}



#pragma  公钥处理
/**
 * 公钥加密
 */
+ (NSString *)EncryptString:(NSString *)context publicKey:(NSString *)publicKey{
    NSData *data = [self EncryptData:[context dataUsingEncoding:NSUTF8StringEncoding] publicKey:publicKey];
    NSString *ret = PIGbase64_encode_data(data);
    return ret;
}
/**
 * 公钥加密
 */
+ (NSData *)EncryptData:(NSData *)contextData publicKey:(NSString *)publicKey{
    if(!contextData || !publicKey){
        return nil;
    }
    SecKeyRef keyRef = [self GetPublicKey:publicKey];
    if(!keyRef){
        return nil;
    }
    return [self encryptData:contextData withKeyRef:keyRef isSign:NO];
}


/**
 * 公钥加密
 */
+ (NSString *)EncryptString:(NSString *)context publicWithContextFile:(NSString *)path
{
    if (!context||!path) return nil;
    
    SecKeyRef keyRef = [self getPublicKeyRefWithContentsOfFile:path];
    if(!keyRef){
        return nil;
    }
    NSData * data = [self encryptData:[context dataUsingEncoding:NSUTF8StringEncoding] withKeyRef:keyRef isSign:NO];
    NSString *ret = PIGbase64_encode_data(data);
    return ret;
}


/**
 * 公钥加密
 */
+ (NSData *)EncryptData:(NSData *)contextData publicWithContextFile:(NSString *)path{
    if (!contextData||!path) return nil;
    
    SecKeyRef keyRef = [self getPublicKeyRefWithContentsOfFile:path];
    if(!keyRef){
        return nil;
    }
    NSData * data = [self encryptData:contextData withKeyRef:keyRef isSign:NO];
    return data;
}


/**
 * 公钥解密
 */
+ (NSString *)DecryptString:(NSString *)context publicKey:(NSString *)publicKey{
    NSData *data = [[NSData alloc] initWithBase64EncodedString:context options:NSDataBase64DecodingIgnoreUnknownCharacters];
    data = [self DecryptData:data publicKey:publicKey];
    NSString *ret = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return ret;
}
/**
 * 公钥解密
 */
+ (NSData *)DecryptData:(NSData *)contextData publicKey:(NSString *)publicKey{
    if(!contextData || !publicKey){
        return nil;
    }
    SecKeyRef keyRef = [self GetPublicKey:publicKey];
    if(!keyRef){
        return nil;
    }
    return [self decryptData:contextData withKeyRef:keyRef];
}


/**
 * 公钥解密
 */
+ (NSData *)DecryptData:(NSData *)contextData publicWithContextFile:(NSString *)path{
    
    if (!contextData||!path) return nil;
    
    SecKeyRef keyRef = [self getPublicKeyRefWithContentsOfFile:path];
    if(!keyRef){
        return nil;
    }
      return [self decryptData:contextData withKeyRef:keyRef];
}
/**
 * 公钥解密
 */
+ (NSString *)DecryptString:(NSString *)context publicWithContextFile:(NSString *)path{
    
    NSData *data = [[NSData alloc] initWithBase64EncodedString:context options:NSDataBase64DecodingIgnoreUnknownCharacters];
    if (!data||!path) return nil;
    
    SecKeyRef keyRef = [self getPublicKeyRefWithContentsOfFile:path];
    if(!keyRef){
        return nil;
    }
    NSData * da = [self decryptData:data withKeyRef:keyRef];
    NSString *ret = [[NSString alloc] initWithData:[self decryptData:data withKeyRef:keyRef] encoding:NSUTF8StringEncoding];
    return ret;
}

@end
