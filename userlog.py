class colors:
   PURPLE = '\033[95m'
   CYAN = '\033[96m'
   DARKCYAN = '\033[36m'
   BLUE = '\033[94m'
   GREEN = '\033[92m'
   YELLOW = '\033[93m'
   RED = '\033[91m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'

class UserLog:
   def info(self, format_string):
      print("{0}[*] {1}{2}".format(colors.GREEN,format_string,colors.END))
   def warn(self, format_string, bold=True):
      if bold:
         print("{0}{1}[*] {2}{3}".format(colors.YELLOW,colors.BOLD,format_string,colors.END))
      else:
         print("{0}[*] {1}{2}".format(colors.YELLOW,format_string,colors.END))
   def error(self, format_string):
      print("{0}[*] {1}{2}".format(colors.RED,format_string,colors.END))
