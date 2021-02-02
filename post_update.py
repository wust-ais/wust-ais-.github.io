#encoding=utf-8
import os

def main():
	os.system("hexo clean")
	os.system("hexo g")
	# print("[*]exec 'echo wiki.w-ais.cn > ./public/CNAME'")
	# os.system("echo wiki.w-ais.cn > ./public/CNAME")
	os.system("hexo d")


if __name__ == '__main__':
	main()

