//
//  PIGSHAUntileFile.m
//  IOSDemo
//
//  Created by CCBLifeCarblet on 2019/3/5.
//  Copyright © 2019年 CCBLifeCarblet. All rights reserved.
//

#import "PIGSHAUntileFile.h"
#import <CommonCrypto/CommonDigest.h>
@implementation PIGSHAUntileFile

+(NSString*)SHA_one_crypt:(NSString*)context {
   NSData * data = [context dataUsingEncoding:NSUTF8StringEncoding];
    const char * inputData = [context UTF8String];
    unsigned char  outData[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(inputData,
            (CC_LONG)strlen(inputData),
            outData);
    NSMutableString * outString = [[NSMutableString alloc]initWithCapacity:CC_SHA1_DIGEST_LENGTH*2];
    for (int i =0 ; i < CC_SHA1_DIGEST_LENGTH; i++) {
        [outString appendFormat:@"%02x",outData[i]];
    }
    return outString;
}

+(NSString*)SHA_two_Five_six_crypt:(NSString*)context {
    
    const char * inputData = [context UTF8String];
    unsigned char  outData[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(inputData,
            (CC_LONG)strlen(inputData),
            outData);
    
    NSMutableString * outString = [[NSMutableString alloc]initWithCapacity:CC_SHA256_DIGEST_LENGTH*2];
    for (int i =0 ; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [outString appendFormat:@"%02x",outData[i]];
    }
    return outString;
}
@end
