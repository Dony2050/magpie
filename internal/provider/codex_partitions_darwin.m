//go:build darwin && cgo

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <stdlib.h>
#include <string.h>

// Read only the named item's ACL metadata. No password bytes are requested.
// This runs in the helper, so disabling interaction cannot change the GUI's
// own keychain operations. The legacy APIs are needed for file keychains.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
char *magpieCodexPartitions(const char *service, const char *account, int *status) {
    @autoreleasepool {
        SecKeychainItemRef item = NULL;
        SecAccessRef access = NULL;
        CFArrayRef list = NULL;
        char *result = NULL;
        *status = SecKeychainSetUserInteractionAllowed(false);
        if (*status != errSecSuccess) goto done;
        *status = SecKeychainFindGenericPassword(NULL, (UInt32)strlen(service), service,
            (UInt32)strlen(account), account, NULL, NULL, &item);
        if (*status != errSecSuccess) goto done;
        *status = SecKeychainItemCopyAccess(item, &access);
        if (*status != errSecSuccess) goto done;
        *status = SecAccessCopyACLList(access, &list);
        if (*status != errSecSuccess) goto done;
        *status = errSecParam;
        for (CFIndex i = 0; i < CFArrayGetCount(list); i++) {
            SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(list, i);
            CSSM_ACL_AUTHORIZATION_TAG tags[256];
            uint32 count = 256;
            if (SecACLGetAuthorizations(acl, tags, &count) != errSecSuccess) continue;
            BOOL partitionACL = NO;
            for (uint32 j = 0; j < count; j++) {
                // CSSM_ACL_AUTHORIZATION_PARTITION_ID, as securityd uses it.
                if (tags[j] == 65538) partitionACL = YES;
            }
            if (!partitionACL) continue;
            CFStringRef description = NULL;
            CFArrayRef apps = NULL;
            SecKeychainPromptSelector selector;
            *status = SecACLCopyContents(acl, &apps, &description, &selector);
            if (apps != NULL) CFRelease(apps);
            if (*status != errSecSuccess || description == NULL) break;
            NSString *hex = (NSString *)description;
            NSMutableData *bytes = [NSMutableData data];
            BOOL valid = hex.length > 0 && hex.length % 2 == 0;
            for (NSUInteger j = 0; valid && j < hex.length; j += 2) {
                NSString *pair = [hex substringWithRange:NSMakeRange(j, 2)];
                unsigned int value = 0;
                NSScanner *scanner = [NSScanner scannerWithString:pair];
                valid = [scanner scanHexInt:&value] && scanner.isAtEnd;
                unsigned char byte = (unsigned char)value;
                if (valid) [bytes appendBytes:&byte length:1];
            }
            id metadata = valid ? [NSPropertyListSerialization propertyListWithData:bytes
                options:NSPropertyListImmutable format:NULL error:NULL] : nil;
            id partitions = [metadata isKindOfClass:[NSDictionary class]] ? metadata[@"Partitions"] : nil;
            if ([partitions isKindOfClass:[NSArray class]]) {
                valid = YES;
                for (id partition in partitions) if (![partition isKindOfClass:[NSString class]]) valid = NO;
                NSData *json = valid ? [NSJSONSerialization dataWithJSONObject:partitions options:0 error:NULL] : nil;
                if (json != nil) {
                    result = malloc(json.length + 1);
                    if (result != NULL) {
                        memcpy(result, json.bytes, json.length);
                        result[json.length] = '\0';
                        *status = errSecSuccess;
                    }
                }
            }
            CFRelease(description);
            if (result == NULL) *status = errSecParam;
            break;
        }
    done:
        if (list != NULL) CFRelease(list);
        if (access != NULL) CFRelease(access);
        if (item != NULL) CFRelease(item);
        return result;
    }
}
#pragma clang diagnostic pop
