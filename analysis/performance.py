import time
import argparse
from subprocess import check_output

def opts_parser():
	
	parser = argparse.ArgumentParser(description='''monitors a proccess' cpu and memory usage on each T seconds''')
	
	# required arguments
	args_group = parser.add_argument_group('required arguments')
	args_group.add_argument('-p', metavar='pid', help='process id', required=True)
	args_group.add_argument('-o', metavar='path', help='log out file path', required=True)
	args_group.add_argument('-t', metavar='time (in seconds)', help='time period between measurements', required=True)

	return parser.parse_args()


def main():
	
	args = opts_parser()
	outfile = open(args.o, "w")
	pid = args.p

	while True:
		# print args

		# ps -p <pid> -o %cpu,%mem,cmd
		subp_output = check_output(["ps", "-p", pid, "-o", "%cpu,%mem"])
		log = subp_output.split("\n")[1]
		outfile.write(log + "\n")

		time.sleep(int(args.t))



if __name__ == '__main__':
	main()