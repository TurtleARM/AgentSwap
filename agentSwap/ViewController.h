//
//  ViewController.h
//  agentSwap
//
//  Created by Davide Ornaghi on 19/09/21.
//

#import <UIKit/UIKit.h>

@interface ViewController : UIViewController<UITextFieldDelegate>

@property (weak, nonatomic) IBOutlet UITextField *directoryTextField;

@property (weak, nonatomic) IBOutlet UILabel *statusLabel;
@property (weak, nonatomic) IBOutlet UISwitch *switchOutlet;
@property (weak, nonatomic) IBOutlet UISwitch *hashesSwitch;

- (IBAction)changeType:(id)sender;

@end

