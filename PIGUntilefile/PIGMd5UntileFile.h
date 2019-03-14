//
//  PIGMd5UntileFile.h
//  IOSDemo
//
//  Created by CCBLifeCarblet on 2019/3/5.
//  Copyright © 2019年 CCBLifeCarblet. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface PIGMd5UntileFile : NSObject

/**32 位 小写*/
+(NSString *)MD5ForLower32Bate:(NSString *)str;

/**32 位 大写*/
+(NSString *)MD5ForUpper32Bate:(NSString *)str;

/**16 位 大写 */
+(NSString *)MD5ForUpper16Bate:(NSString *)str;

/**16 位小写*/
+(NSString *)MD5ForLower16Bate:(NSString *)str;
@end

NS_ASSUME_NONNULL_END
