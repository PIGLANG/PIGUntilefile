//
//  PIGAESUntileFile.m
//  IOSDemo
//
//  Created by CCBLifeCarblet on 2019/3/5.
//  Copyright © 2019年 CCBLifeCarblet. All rights reserved.
//

#import "PIGAESUntileFile.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#import "NSObject+PIGCategory.h"
@implementation PIGAESUntileFile




/**
 * 加密
 * @param context 加密的内容
 * @param key 秘钥
 * @param iv 偏移量
 */
+(NSString*)AESEncrypt:(NSString * )context key:(NSString*)key iv:(nullable NSString *)iv
{
    return PIGbase64_encode_data([self opention:context key:key iv:iv type:kCCEncrypt]);
}


/**
 * 解密
 * @param context 解密的内容
 * @param key 秘钥
 * @param iv 偏移量
 */
+(NSData*)AESDecrypt:(NSString * )context key:(NSString*)key iv:(nullable NSString *)iv
{
    NSData * data =  PIGbase64_decode(context);
    
    context = [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding];
    
    return  [self opention:context key:key iv:iv type:kCCDecrypt];
}


+(NSData * )opention:(NSString * )context key:(NSString*)key iv:(NSString *)iv type:(uint32_t)type {
    
    NSData * data = [context dataUsingEncoding:NSUTF8StringEncoding];
    
    char keyPtr[kCCKeySizeAES128 +1];   //kCCKeySizeAES128是加密位数 可以替换成256位的
    
    bzero(keyPtr, sizeof(keyPtr));// keyPtr 全部置位零
    
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    //偏移量
    char ivPtr[kCCKeySizeAES128+1];
    
    bzero(ivPtr, sizeof(ivPtr));
    
    size_t outSize = data.length+sizeof(keyPtr);
    
    void * DataOut = malloc(outSize);
    
    [iv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    
    // kCCEncrypt 加密  kCCAlgorithmAES128 AES128 格式
    CCCryptorStatus status =  CCCrypt(type,
                                      kCCAlgorithmAES128,
                                      kCCOptionPKCS7Padding,
                                      keyPtr,
                                      sizeof(keyPtr),
                                      ivPtr,
                                      data.bytes,
                                      data.length,
                                      DataOut,
                                      outSize,0);
    if (status==kCCSuccess) {
        return [NSData dataWithBytesNoCopy:DataOut length:outSize];
    }
    free(DataOut);
    return nil;
}

@end
