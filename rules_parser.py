#!/bin/python
#-*- coding:utf-8 -*-


class rules():
	"""
	CLASS pour les règles
	"""
	
	action=False
	protocole=False
	s_ip=False
	s_port=False
	direction=False
	d_ip=False
	d_port=False
	msg=False
	content=False
	
	def __init__(self, action, protocole, s_ip, s_port, direction, d_ip, d_port, msg, content):
		self.action = action
		self.protocole = protocole
		self.s_ip = s_ip
		self.s_port = s_port
		self.direction = direction
		self.d_ip = d_ip
		self.d_port = d_port
		self.msg = msg
		self.content = content


	def __repr__(self):
		print "Action : " + self.action + "\nProtocole : "+ self.protocole+ "\nSource IP : "+self.s_ip+"\nSource Port : "+self.s_port+"\nDirection : "+self.direction+"\nDestination IP : "+self.d_ip+"\nDestination Port : "+self.d_port+ "\nMessage : " + self.msg + "\nContenu : " + self.content

	def change_ip(self, nouvelle_ip):
		self.s_ip = nouvelle_ip

	def get_s_ip(self):
		return self.s_ip

	def set_s_ip(self, new):
		self.s_ip = new

	def get_action(self):
		return self.action

	def set_action(self, new):
		self.action = new

	def get_protocole(self):
		return self.protocole

	def set_protocole(self, new):
		self.protocole = new

	def get_s_port(self):
		return self.s_port

	def set_s_port(self, new):
		self.s_port = new

	def get_direction(self):
		return self.direction

	def set_direction(self, new):
		self.direction = new

	def get_d_ip(self):
		return self.d_ip

	def set_d_ip(self, new):
		self.d_ip = new

	def get_d_port(self):
		return self.d_port

	def set_d_port(self, new):
		self.d_port = new

	def get_msg(self):
		return self.msg

	def set_msg(self, new):
		self.msg = new

	def get_content(self):
		return self.content

	def set_content(self, new):
		self.content = new

def read_rules(protocole):
	with open("IPS_"+protocole+".rules", "r") as fichier:
		lines = fichier.readlines()


		action_direction = lines[0]
		action = action_direction.split(" ")[0]
		protocole = action_direction.split(" ")[1]
		s_ip = action_direction.split(" ")[2]
		s_port = action_direction.split(" ")[3]
		direction = action_direction.split(" ")[4]
		d_ip = action_direction.split(" ")[5]
		d_port = action_direction.split(" ")[6]
		msg = lines[1].split("msg:\"")[1].split("\";")[0]
		content = lines[2].split("content:\"")[1].split("\")")[0]
		
		return action, protocole, s_ip, s_port, direction, d_ip, d_port, msg, content
		fichier.close()

def match_rules_input(input_packet, rules):
	if rules in input_packet:
		return False
	else:
		return True

def main():
	regle = read_rules("HTTP")
	regle = rules(regle[0],regle[1],regle[2],regle[3],regle[4],regle[5],regle[6],regle[7],regle[8])

	# Test du matchin
	test_matching = match_rules_input("caca je te pueOR 1=1#", regle.content)
	if test_matching==False:
		print regle.msg
	elif test_matching==True:
		print "Accept"


main()
