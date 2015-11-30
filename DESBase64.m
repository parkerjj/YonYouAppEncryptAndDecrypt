//
//  DESBase64.m
//  Secret Socks
//
//  Created by DevPaK on 15-11-30.
//  Copyright 2011年 I Wont Tell U. All rights reserved.
//

#import "DESBase64.h"
#import "GZIP.h"

static char iv[] = { 18, 52, 86, 120, -112, -85, -51, -17 };
#define kYonYouDESKey   @"G51-NIPR"



@implementation DESBase64

+ (NSString*)TripleDES:(NSData*)data encryptOrDecrypt:(CCOperation)encryptOrDecrypt{
    
    const void *vplainText;
    size_t plainTextBufferSize;
    NSData *oriData = data;
    
    if (encryptOrDecrypt == kCCDecrypt)
    {
        oriData = [oriData gunzippedData];
        NSData *EncryptData = [GTMBase64 decodeData:oriData];
        plainTextBufferSize = [EncryptData length];
        vplainText = [EncryptData bytes];
    }
    else
    {
        plainTextBufferSize = [data length];
        vplainText = (const void *)[data bytes];
    }
    
    
    CCCryptorStatus ccStatus;
    uint8_t *bufferPtr = NULL;
    size_t bufferPtrSize = 0;
    size_t movedBytes = 0;
    
    bufferPtrSize = (plainTextBufferSize + kCCBlockSizeDES) & ~(kCCBlockSizeDES - 1);
    bufferPtr = malloc( bufferPtrSize * sizeof(uint8_t));
    memset((void *)bufferPtr, 0x0, bufferPtrSize);
    
    const void *vkey = (const void *) [kYonYouDESKey UTF8String];
    const void *vinitVec = (const void *) iv;

    
    ccStatus = CCCrypt(encryptOrDecrypt,
                       kCCAlgorithmDES,
                       kCCOptionPKCS7Padding,
                       vkey, //"123456789012345678901234", //key
                       kCCKeySizeDES,
                       vinitVec, //"init Vec", //iv,
                       vplainText, //"Your Name", //plainText,
                       plainTextBufferSize,
                       (void *)bufferPtr,
                       bufferPtrSize,
                       &movedBytes);
    if (ccStatus == kCCSuccess) NSLog(@"SUCCESS");
    else if (ccStatus == kCCParamError) return @"PARAM ERROR";
     else if (ccStatus == kCCBufferTooSmall) return @"BUFFER TOO SMALL";
     else if (ccStatus == kCCMemoryFailure) return @"MEMORY FAILURE";
     else if (ccStatus == kCCAlignmentError) return @"ALIGNMENT";
     else if (ccStatus == kCCDecodeError) return @"DECODE ERROR";
     else if (ccStatus == kCCUnimplemented) return @"UNIMPLEMENTED";
    
    NSString *result;
    
    if (encryptOrDecrypt == kCCDecrypt)
    {
        NSData *data = [NSData dataWithBytes:(const void *)bufferPtr
                                      length:(NSUInteger)movedBytes];
        result = [[NSString alloc] initWithData: data
                                        encoding:NSASCIIStringEncoding];
    }
    else
    {
        NSData *myData = [NSData dataWithBytes:(const void *)bufferPtr length:(NSUInteger)movedBytes];
        result = [GTMBase64 stringByEncodingData:myData];
    }
    
    return result;
    
} 

@end
