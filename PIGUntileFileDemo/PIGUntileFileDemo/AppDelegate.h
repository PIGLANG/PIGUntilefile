//
//  AppDelegate.h
//  PIGUntileFileDemo
//
//  Created by zhoumeineng on 2019/4/13.
//  Copyright © 2019 zhoumeineng. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <CoreData/CoreData.h>

@interface AppDelegate : UIResponder <UIApplicationDelegate>

@property (strong, nonatomic) UIWindow *window;

@property (readonly, strong) NSPersistentContainer *persistentContainer;

- (void)saveContext;


@end

