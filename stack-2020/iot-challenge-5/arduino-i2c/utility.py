# out=(0b1111<<4) | 0b1000
# print(out)

import serial
import sys
import os
import numpy as np
import pandas as pd
import ast
import time


def main():

    print("textin")
    convertNumpy("textin")
    print("traces")
    convertNumpy("traces")
    return

    dir=os.getcwd()
    path=os.path.join(dir,"decoded_i2c.txt")
    outPath=os.path.join(dir,"processed.csv")
    in_data=pd.read_csv(path,sep=',')
    vectConvert=np.vectorize(convertStr,otypes=[np.int32])
    data_np=vectConvert(in_data["Data"].to_numpy())
    print(data_np)
    np.savetxt(outPath,data_np,fmt="%i",delimiter="\t")

class sender():
    # For sending stuff to arduino
    def __init__(self,serialPath="/dev/ttyACM0",csvPath="processed.csv"):
        # Opens serial port and loads data from file
        self.serObj=serial.Serial(serialPath,9600)
        self.data=np.genfromtxt(os.path.join(os.getcwd(),csvPath),dtype=np.int32)
        self.index=0
        print(self.data)

    def send_a_bunch(self,n):
        # Sends n lines of data to Arduino
        startIndex=self.index
        for i in range(n):
            toSend=self.data[startIndex+i]
            toSend=(str(toSend)+"\n")
            print(toSend)
            self.serObj.write(toSend.encode())
            self.index+=1
            # Some delay is necessary to let the LCD respond
            time.sleep(0.1)

def convertStr(string):
    # converts shittily formatted string into nice integers so that we can feed it to arduino
    # print(string)
    if(string=="' '"):
        return 32
    elif(string=="COMMA"):
        return 44
    elif(string[0]=="'"):
        return int(string.strip(string[0]))
    elif(string=="\\r"):
        return 13
    elif(string=="\\t"):
        return 9
    else:
        return ord(string)
    
def convertNumpy(fileName):
    path=os.path.join(os.getcwd(),"RESULT",fileName+".npy")
    array=np.load(path)
    print(array)
    np.savetxt(os.path.join(os.getcwd(),"RESULT",fileName+".txt"),array,delimiter="\t")

if __name__=="__main__":
    main()