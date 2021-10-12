//
//  ViewController.m
//  agentSwap
//
//  Created by Davide Ornaghi on 19/09/21.
//

#import "ViewController.h"
#import "jailbreak.h"

@interface ViewController ()

@end

@implementation ViewController
@synthesize switchOutlet;
@synthesize statusLabel;
@synthesize directoryTextField;
@synthesize hashesSwitch;

- (void)viewDidLoad {
    [super viewDidLoad];
    directoryTextField.delegate = self;
    statusLabel.numberOfLines = 0;
}

-(BOOL)textFieldShouldReturn:(UITextField *)textField {
    [textField resignFirstResponder];
    return YES;
}

- (IBAction)jailbreak:(id)sender {
    NSString *trimmed = [directoryTextField.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    [statusLabel setText:@"Running the exploit..."];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        get_tfp0();
        dispatch_sync(dispatch_get_main_queue(), ^{
            [self.statusLabel setText:@"Patching the kernel..."];
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                if (!patch_kernel()) {
                    [self.statusLabel setText:@"Error"];
                    return;
                }
                dispatch_sync(dispatch_get_main_queue(), ^{
                    if (self.hashesSwitch.on) {
                        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                            write_hashes([trimmed UTF8String]);
                        });
                    }
                    if (self.switchOutlet.on) {
                        NSString *cmd = [NSString stringWithFormat:@"Spawning a shell. Run the following command: echo \"binbag tar -cf - %@ 2> /var/stderr\" | nc -w 2 {device IP} 4141 > {archive path}", trimmed];
                        [self.statusLabel setText:cmd];
                        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                            extract();
                        });
                    } else {
                        [self.statusLabel setText:@"Extracting files..."];
                        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                            char *outArchive = calloc(200, sizeof(char));
                            extractArchive([trimmed UTF8String], outArchive);
                            dispatch_sync(dispatch_get_main_queue(), ^{
                                [self.statusLabel setText:@"Done. You can find the archive in the Media directory"];
                            });
                        });
                    }
                });
            });
        });
    });
    NSLog(@"Done.");
}

- (IBAction)changeType:(id)sender {

}
@end
