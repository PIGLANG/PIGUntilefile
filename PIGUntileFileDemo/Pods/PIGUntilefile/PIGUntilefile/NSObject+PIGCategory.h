//
//  NSObject+PIGCategory.h
//  IOSDemo
//
//  Created by CCBLifeCarblet on 2019/3/28.
//  Copyright © 2019年 CCBLifeCarblet. All rights reserved.
//

#import <Foundation/Foundation.h>


NS_ASSUME_NONNULL_BEGIN

@interface NSObject (PIGCategory)
//解码
NSString * PIGbase64_encode_data(NSData*data);

//解码
NSData * PIGbase64_decode(NSString*base64String);


//解码
NSString* PIGBase64Decoding(NSString *baseString);

//解码
NSString* PIGBase64Encoding(NSString *string );


/**
 二进制转换为十进制
 
 @param binary 二进制数
 @return 十进制数
 */
+ (NSInteger)getDecimalByBinary:(NSString *)binary;



// bytes 数组 转 16 进制 字符串
+(NSString *) parseByteArray2HexString:(Byte[]) bytes;



/**
 二进制转换成十六进制
 
 @param binary 二进制数
 @return 十六进制数
 */
+ (NSString *)getHexByBinary:(NSString *)binary ;



/**二进制的异或运算 返回 二进制 字符串*/
+(NSString*)XORMath:(NSString*)number_one nummber_two:(NSString*)number_two;



/**十六进制字符串转二进制*/
+ (NSString *)getBinaryByHex:(NSString *)hex ;



// 十六进制转换为普通字符串的。
+ (NSString *)stringFromHexString:(NSString *)hexString;



//普通字符串转换为十六进制的。
+(NSString*)hexStringFromString:(NSString*)string;



//普通字符串转ASCII
+(int)stringToASSCII:(NSString*)string;


// 异或 并且 转 16 进制

+(NSString*)ASSCIIXor:(NSString*)str numb:(int)numb;


// 16 进制 转 ASSCII 并且 异或

+(NSString*)XorASSCII:(NSString*)str numb:(int)numb;


// 普通字符 异或操作
+(NSString*)stringXORstring:(id)one two:(id)two;

@end

NS_ASSUME_NONNULL_END
