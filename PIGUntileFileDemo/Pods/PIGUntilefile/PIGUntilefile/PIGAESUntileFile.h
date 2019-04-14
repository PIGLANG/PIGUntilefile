//
//  PIGAESUntileFile.h
//  IOSDemo
//
//  Created by CCBLifeCarblet on 2019/3/5.
//  Copyright © 2019年 CCBLifeCarblet. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface PIGAESUntileFile : NSObject


/**
 * 加密
 * @param context 加密的内容
 * @param key 秘钥
 * @param iv 偏移量
 */
+(NSString*)AESEncrypt:(NSString * )context key:(NSString*)key iv:(nullable NSString *)iv;


/**
 * 解密
 * @param context 解密的内容
 * @param key 秘钥
 * @param iv 偏移量
 */
+(NSData*)AESDecrypt:(NSString * )context key:(NSString*)key iv:(nullable NSString *)iv;

@end

