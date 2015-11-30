//
//  DESBase64.h
//  Secret Socks
//
//  Created by DevPaK on 15-11-30.
//  Copyright 2011年 I Wont Tell U. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCryptor.h>
#import "GTMBase64.h"  

@interface DESBase64 : NSObject


/**
 *  用友解密
 *
 *  @param data             传入Data
 *  @param encryptOrDecrypt 加密/解密
 *
 *  @return 加解密后的Base64String
 */
+ (NSString*)TripleDES:(NSData*)data encryptOrDecrypt:(CCOperation)encryptOrDecrypt;
    
@end
