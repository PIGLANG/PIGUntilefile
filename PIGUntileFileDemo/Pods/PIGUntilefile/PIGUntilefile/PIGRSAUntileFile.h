//
//  PIGRSAUntileFile.h
//  IOSDemo
//
//  Created by CCBLifeCarblet on 2019/3/4.
//  Copyright © 2019年 CCBLifeCarblet. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface PIGRSAUntileFile : NSObject


/**
 *  加密方法 .der 格式
 *
 * @param context 加密内容
 * @param path  der文件 路径
 */
+(NSString*)EncryptString:(NSString*)context publicWithContextFile:(NSString*)path;


/**
 *  解密方法 .p12 格式
 *
 * @param context 需要解密内容
 * @param path  p12文件 路径
 * @param password 文件打开的密码
 */
+(NSString*)DecryptString:(NSString*)context privateWithContextFile:(NSString*)path password:(NSString*)password;


// 公钥解密
+ (NSString *)DecryptString:(NSString *)context publicKey:(NSString *)publicKey;



/**
 *  加密方法
 *
 * @param context 加密内容
 * @param key  加密的key
 */
+(NSString*)EncryptString:(NSString*)context publicKey:(NSString*)key;


/**
 *  解密方法
 *
 * @param context 需要解密内容
 * @param key  解密的key
 */
+(NSString*)DecryptString:(NSString*)context privateKey:(NSString*)key;

@end

NS_ASSUME_NONNULL_END
