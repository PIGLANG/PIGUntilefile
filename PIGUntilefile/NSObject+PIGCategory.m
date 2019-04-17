//
//  NSObject+PIGCategory.m
//  IOSDemo
//
//  Created by CCBLifeCarblet on 2019/3/28.
//  Copyright © 2019年 CCBLifeCarblet. All rights reserved.
//

#import "NSObject+PIGCategory.h"

@implementation NSObject (PIGCategory)

//编码
NSString * PIGbase64_encode_data(NSData*data){
    data = [data base64EncodedDataWithOptions:(0)];
    NSString * ret = [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding];
    return ret;
}

//64 解码
NSData * PIGbase64_decode(NSString*base64String){ //base64String 为 base64 字符串
    NSData * data = [[NSData alloc]initWithBase64EncodedString:base64String options:(NSDataBase64DecodingIgnoreUnknownCharacters)];
    return data;
}

//编码
NSString* PIGBase64Encoding(NSString *string ){
    NSData * data= [string dataUsingEncoding:NSUTF8StringEncoding];
    NSString * RSAKey = [data base64EncodedStringWithOptions:(0)];
    return RSAKey;
}

//解码
NSString* PIGBase64Decoding(NSString *baseString){
    NSData * data = [[NSData alloc]initWithBase64EncodedString:baseString options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSString * RSAKey = [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding];
    return RSAKey;
}

// 16 进制 转 ASSCII 并且 异或

+(NSString*)XorASSCII:(NSString*)str numb:(int)numb{
    NSString * hex = [self getBinaryByHex:str];//转成 2 进制
    NSString * hs = @"";
    for (int i = 0; i<hex.length; i+=8) {
        NSInteger number = [self getDecimalByBinary:[hex substringWithRange:NSMakeRange(i, 8)]];
        char  c = numb ^ number;
        NSString * st = [NSString stringWithFormat:@"%c",c];
        hs = [hs stringByAppendingString:st];
    }
    return hs;
}




// 异或 并且 转 16 进制

+(NSString*)ASSCIIXor:(NSString*)str numb:(int)numb{
    NSString * st = @"";
    for (int i = 0; i <str.length; i++) {
        int assic = [str characterAtIndex:i];
        int c = (assic ^ numb);
        NSString * strs = [NSString stringWithFormat:@"%x",c&0xff];
        if (strs.length<2) {
            st = [st stringByAppendingFormat:@"0%@",strs];
        }else{
            st = [st stringByAppendingFormat:@"%@",strs];
        }
        
    }
    return st;
}

//普通字符串转ASCII
+(int)stringToASSCII:(NSString*)string{
    NSMutableString * st = [[NSMutableString alloc]init];
    for (int i = 0; i <string.length; i++) {
        int assic = [string characterAtIndex:i];
        NSString * str = [NSString stringWithFormat:@"%d",assic];
        [st appendString:str];
    }
    return  [st intValue];
    
}




// 普通字符 异或操作
+(NSString*)stringXORstring:(id)one two:(id)two{
    
    NSString * hex_1 = [self hexStringFromString:one]; //普通字符 转 16 进制
    
    NSString * Binary_1 = [self getBinaryByHex:hex_1];// 16 进制 转 2 进制
    
    NSString * hex_2 = [self hexStringFromString: two]; //普通字符 转 16 进制
    
    NSString *  Binary_2 = [self getBinaryByHex:hex_2]; // 16 进制 转 2 进制
    
    NSString * xor =  [self XORMath:Binary_1 nummber_two:Binary_2];// 二进制 异或比较
    
    NSString * hex = [self getHexByBinary:xor];// 二进制 转 16 进制
    
    NSString * res = [self stringFromHexString:hex]; //16 进制 转 普通字符串
    
    return res;
}


//普通字符串转换为十六进制的。
+(NSString*)hexStringFromString:(NSString*)string {
    NSData * data = [string dataUsingEncoding:NSUTF8StringEncoding];
    Byte * bytes = (Byte *)data.bytes;
    NSString * hexStr = @"";
    for (int i = 0; i<data.length; i++) {
        int a = bytes[i];
        NSString * newHexStr = [NSString stringWithFormat:@"%x",a];
        if (newHexStr.length<2) {
            hexStr = [NSString stringWithFormat:@"%@0%@",hexStr,newHexStr];
        }else{
            hexStr = [NSString stringWithFormat:@"%@%@",hexStr,newHexStr];
        }
    }
    return hexStr;
}


// 十六进制转换为普通字符串的。
+ (NSString *)stringFromHexString:(NSString *)hexString { //
    
    char *myBuffer = (char *)malloc((int)[hexString length] / 2 + 1);
    bzero(myBuffer, [hexString length] / 2 + 1);
    for (int i = 0; i < [hexString length] - 1; i += 2) {
        unsigned int anInt;
        NSString * hexCharStr = [hexString substringWithRange:NSMakeRange(i, 2)];
        NSScanner * scanner = [[NSScanner alloc] initWithString:hexCharStr] ;
        [scanner scanHexInt:&anInt];
        myBuffer[i / 2] = (char)anInt;
    }
    NSString *unicodeString = [NSString stringWithCString:myBuffer encoding:4];
    return unicodeString;
}


/**十六进制字符串转二进制*/
+ (NSString *)getBinaryByHex:(NSString *)hex {
    NSMutableDictionary *hexDic = [[NSMutableDictionary alloc] initWithCapacity:16];
    [hexDic setObject:@"0000" forKey:@"0"];
    [hexDic setObject:@"0001" forKey:@"1"];
    [hexDic setObject:@"0010" forKey:@"2"];
    [hexDic setObject:@"0011" forKey:@"3"];
    [hexDic setObject:@"0100" forKey:@"4"];
    [hexDic setObject:@"0101" forKey:@"5"];
    [hexDic setObject:@"0110" forKey:@"6"];
    [hexDic setObject:@"0111" forKey:@"7"];
    [hexDic setObject:@"1000" forKey:@"8"];
    [hexDic setObject:@"1001" forKey:@"9"];
    [hexDic setObject:@"1010" forKey:@"A"];
    [hexDic setObject:@"1011" forKey:@"B"];
    [hexDic setObject:@"1100" forKey:@"C"];
    [hexDic setObject:@"1101" forKey:@"D"];
    [hexDic setObject:@"1110" forKey:@"E"];
    [hexDic setObject:@"1111" forKey:@"F"];
    NSMutableString *binary = [NSMutableString string];
    for (int i = 0; i < hex.length; i++) {
        NSString *key = [hex substringWithRange:NSMakeRange(i, 1)];
        key = key.uppercaseString;
        NSString *binaryStr = hexDic[key];
        [binary appendString:[NSString stringWithFormat:@"%@",binaryStr]];
    }
    return binary;
}

/**二进制的异或运算 返回 二进制 字符串*/
+(NSString*)XORMath:(NSString*)number_one nummber_two:(NSString*)number_two{
    
    NSInteger len = number_one.length>number_two.length?number_one.length:number_two.length;
    
    NSString *src = @"";
    
    for (NSInteger idx = (len-1); idx>=0; idx--) {
        char A = '0';
        char B = '0' ;
        if ((idx<number_one.length)) {
            A =  [number_one characterAtIndex:idx];
        }
        if ((idx<number_two.length)) {
            B = [number_two characterAtIndex:idx];
        }
        char c = A ^ B;
        src = [[NSString stringWithFormat:@"%d",c] stringByAppendingString:src];
    }
    return src;
}



/**
 二进制转换成十六进制
 
 @param binary 二进制数
 @return 十六进制数
 */
+ (NSString *)getHexByBinary:(NSString *)binary {
    
    NSMutableDictionary *binaryDic = [[NSMutableDictionary alloc] initWithCapacity:16];
    [binaryDic setObject:@"0" forKey:@"0000"];
    [binaryDic setObject:@"1" forKey:@"0001"];
    [binaryDic setObject:@"2" forKey:@"0010"];
    [binaryDic setObject:@"3" forKey:@"0011"];
    [binaryDic setObject:@"4" forKey:@"0100"];
    [binaryDic setObject:@"5" forKey:@"0101"];
    [binaryDic setObject:@"6" forKey:@"0110"];
    [binaryDic setObject:@"7" forKey:@"0111"];
    [binaryDic setObject:@"8" forKey:@"1000"];
    [binaryDic setObject:@"9" forKey:@"1001"];
    [binaryDic setObject:@"A" forKey:@"1010"];
    [binaryDic setObject:@"B" forKey:@"1011"];
    [binaryDic setObject:@"C" forKey:@"1100"];
    [binaryDic setObject:@"D" forKey:@"1101"];
    [binaryDic setObject:@"E" forKey:@"1110"];
    [binaryDic setObject:@"F" forKey:@"1111"];
    
    if (binary.length % 4 != 0) {
        
        NSMutableString *mStr = [[NSMutableString alloc]init];;
        for (int i = 0; i < 4 - binary.length % 4; i++) {
            
            [mStr appendString:@"0"];
        }
        binary = [mStr stringByAppendingString:binary];
    }
    NSString *hex = @"";
    for (int i=0; i<binary.length; i+=4) {
        
        NSString *key = [binary substringWithRange:NSMakeRange(i, 4)];
        NSString *value = [binaryDic objectForKey:key];
        if (value) {
            
            hex = [hex stringByAppendingString:value];
        }
    }
    return hex;
}

// bytes 数组 转 16 进制 字符串
+(NSString *) parseByteArray2HexString:(Byte[]) bytes
{
    NSMutableString *hexStr = [[NSMutableString alloc]init];
    int i=0 ;
    if (bytes) {
        while (bytes[i]!='\0') {
            NSString * hexbyte = [NSString stringWithFormat:@"%x",bytes[i]&0xff];
            [hexStr appendString:hexbyte];
            if([hexbyte length]<2)
                [hexStr appendFormat:@"0%@", hexbyte];
            else
                [hexStr appendFormat:@"%@", hexbyte];
            i++;
        }
    }
    return hexStr;
}

/**
 二进制转换为十进制
 
 @param binary 二进制数
 @return 十进制数
 */
+ (NSInteger)getDecimalByBinary:(NSString *)binary {
    
    NSInteger decimal = 0;
    for (int i=0; i<binary.length; i++) {
        
        NSString *number = [binary substringWithRange:NSMakeRange(binary.length - i - 1, 1)];
        if ([number isEqualToString:@"1"]) {
            
            decimal += pow(2, i);
        }
    }
    return decimal;
}
@end
