#include <Wire.h>
#include <LiquidCrystal_I2C.h>

LiquidCrystal_I2C lcd(0x27,16,2);

void setup() {
  // put your setup code here, to run once:
  Serial.begin(9600);
  lcd.init();
  lcd.backlight();

  delay(500);
  lcd.clear();
//  lcd.print("Hello");

}

void loop() {
//   put your main code here, to run repeatedly:
//  Serial.println("hello");
  
//  Wire.beginTransmission(0x27);
  if(Serial.available()){
    Wire.beginTransmission(0x27);
    String str=Serial.readStringUntil('\n');
    byte x=str.toInt();
    Serial.println(x);
    Wire.write(x);
    Wire.endTransmission();    
  }
//  Wire.endTransmission();
//  delay(100);
}
