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
 * 公钥加密
 */
+ (NSString *)EncryptString:(NSString *)context publicKey:(NSString *)publicKey;


/**
 * 公钥加密
 */
+ (NSData *)EncryptData:(NSData *)contextData publicKey:(NSString *)publicKey;


/**
 * 公钥加密
 */
+ (NSString *)EncryptString:(NSString *)context publicWithContextFile:(NSString *)path;

/**
 * 公钥加密
 */
+ (NSData *)EncryptData:(NSData *)contextData publicWithContextFile:(NSString *)path;

/**
 * 公钥解密
 */
+ (NSString *)DecryptString:(NSString *)context publicKey:(NSString *)publicKey;


/**
 * 公钥解密
 */
+ (NSData *)DecryptData:(NSData *)contextData publicKey:(NSString *)publicKey;

/**
 * 公钥解密
 */
+ (NSString *)DecryptString:(NSString *)context publicWithContextFile:(NSString *)path;



/**
 * 公钥解密
 */
+ (NSData *)DecryptData:(NSData *)contextData publicWithContextFile:(NSString *)path;




/**
 * 私钥加密
 * @param context 加密内容
 * @param privateKey 私钥
 */
+(NSString *)EncryptString:(NSString *)context privateKey:(NSString *)privateKey;




/**
 * 私钥加密
 * @param contextData 加密内容
 * @param privateKey 私钥
 */
+ (NSData *)EncryptData:(NSData *)contextData privateKey:(NSString *)privateKey;




/**
 * 私钥解密
 *
 */
+ (NSData *)DecryptData:(NSData *)contextData privateKey:(NSString *)privateKey;


/**
 * 私钥解密
 *
 */

+ (NSString *)DecryptString:(NSString *)str privateKey:(NSString *)privateKey;



@end

NS_ASSUME_NONNULL_END
