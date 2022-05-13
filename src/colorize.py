"""
Defines a simple helper class on top of colorama for stateful string colorization.
"""

# Copyright Amazon.com, Inc. and its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT



########################################################################################################################
# Imports
########################################################################################################################

try:
  import colorama
except ImportError as err:
  print(err)
  print("Please install the required module (ex: 'pip install <package>').")
  exit()



########################################################################################################################
# Main Class
########################################################################################################################

class Colorize:
  """
  Simple helper class on top of colorama to always append colorama.Style.RESET_ALL and hold state:
   - Enable/Disable Colorization
   - Value-to-Color Map to Auto-Colorize Known Values
   - Default Color for Unknown Values
  """

  Enabled = True
  ColorMap = None
  DefaultColor = None

  def __init__(self, color_map = None, default_color = None, enabled = True):
    """
    :param color_map:      Optional value-to-color map for auto-colorization.
    :param default_color:  Optional color for unknown values.
    :param enabled:        Colorization is only performed when enabled.
    """

    self.Enabled = enabled
    self.ColorMap = color_map
    self.DefaultColor = default_color

  def Colorize(self, insie, color = None):
    """
    Return the input string colorized by (in order) 'color' parameter, or 'color_map' lookup, or 'default_color'.

    :param insie:         Value to colorize (and convert to string as necessary).
    :param color:         Color to use (omit to use 'color_map' or 'default_color').
    :return:              Colorized input value.
    """

    if not self.Enabled:
      outsie = insie

    elif insie is None or insie == '':
      outsie = insie

    elif color:
      outsie = color + str(insie) + colorama.Style.RESET_ALL

    else:
      outsie = self.ColorMap.get(insie, self.DefaultColor) + str(insie) + colorama.Style.RESET_ALL

    return outsie



########################################################################################################################
# Basic Testing
########################################################################################################################

if __name__ == "__main__":

  print()
  print("Running Colorize test cases...")
  print()

  import sys

  class Color:
    Dev          = colorama.Fore.YELLOW
    Info         = colorama.Style.DIM + colorama.Fore.WHITE
    Error        = colorama.Fore.RED
    BoolTrue     = colorama.Fore.GREEN
    BoolFalse    = colorama.Fore.RED
    Dot          = colorama.Style.DIM + colorama.Fore.WHITE
    Default      = colorama.Fore.CYAN

  color_map = {
    'Dev':       Color.Dev,
    'Info':      Color.Info,
    'Error':     Color.Error,
    '.':         Color.Dot,
    True:        Color.BoolTrue,
    False:       Color.BoolFalse,
  }

  c = Colorize(color_map, Color.Default)

  print(c.Colorize("Error", colorama.Fore.CYAN) + " <-- Should be CYAN.")

  print(c.Colorize(None), "<-- Should not be colorized.")
  print(c.Colorize('') + "<-- Should be empty string.")

  print(c.Colorize("Dev"))
  print(c.Colorize("Info"))
  print(c.Colorize("Error"))
  print(c.Colorize(True))
  print(c.Colorize(False))

  print(c.Colorize("Should be the default color (CYAN)."))

  for i in range (0, 10):
    sys.stdout.write(c.Colorize('.'))
  print(" <-- Should be single line of 10 dark-gray dots.")

  c.Enabled = False

  print(c.Colorize("This line should not be colorized.", Color.Error))
