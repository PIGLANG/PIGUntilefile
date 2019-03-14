//
//  PIG3DesUntileFile.h
//  IOSDemo
//
//  Created by CCBLifeCarblet on 2019/3/5.
//  Copyright © 2019年 CCBLifeCarblet. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface PIG3DesUntileFile : NSObject
/**
 * 加密
 * @param context 加密的内容
 * @param key 秘钥
 */
+(NSString*)ThreeDESEncrypt:(NSString * )context key:(NSString*)key;



/**
 * 解密
 * @param context 解密的内容
 * @param key 秘钥
 */
+(NSData*)ThreeDESDecrypt:(NSString * )context key:(NSString*)key;



@end

NS_ASSUME_NONNULL_END
