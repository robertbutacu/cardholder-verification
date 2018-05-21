package com.cardholder.verification;

public class Account {
	public short balance;
	public byte[] pin;
	
	public Account(){
		balance = (short) 0;
	}
	
	public void debit(short amount) {
		if(amount > balance)
			throw new IllegalArgumentException("Not enough money for payment!");
		
		balance -= amount;
	}
	
	public void credit(short amount){
		if(this.balance + amount > 10000)
			throw new IllegalArgumentException("Max amount exceeded");
		
		this.balance += amount;
	}
	
	public short getBalance(short amount) {
		return this.balance;
	}
	
	public boolean isCorrectPin(byte[] pin){
		if(this.pin.length != pin.length)
			return false;
		
		for(int i = 0 ; i < this.pin.length; i++){
			if(this.pin[i] != pin[i])
				return false;
		}
		
		return true;
	}
}