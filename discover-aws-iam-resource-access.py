#!/usr/bin/env python

"""
Discover AWS IAM identities (users and roles) with specified access to specified resources.
"""

# Copyright Amazon.com, Inc. and its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT



########################################################################################################################
# Documentation
########################################################################################################################

# See the README.md file.



########################################################################################################################
# Imports
########################################################################################################################

import sys
import time
import json
import argparse
from datetime import datetime, timezone, timedelta

from src.colorize import Colorize

try:
  import boto3
  import pandas
  import colorama
except ImportError as err:
  print(err)
  print("Please install the required module (ex: 'pip install <package>').")
  exit()



########################################################################################################################
# Confirm required Python version.
########################################################################################################################

if sys.version_info < (3, 9):
  print("Detected Python version ", sys.version_info.major, ".", sys.version_info.minor, sep='', end='')
  print(", but this script requires Python 3.9+. Aborting.")
  exit()



########################################################################################################################
# Global Constants
########################################################################################################################

# IAM actions that indirectly provide elevated access.
IAM_ROLE_ACTIONS = ['iam:AssumeRole', 'iam:PassRole']
IAM_POLICY_ACTIONS = ['iam:Attach*', 'iam:Create*', 'iam:Put*']



########################################################################################################################
# Output Text Colorization
########################################################################################################################

# Defines a color for each type of output.
class Color:
  Dev          = colorama.Fore.YELLOW
  Info         = colorama.Style.DIM + colorama.Fore.WHITE
  Error        = colorama.Fore.RED
  Section      = colorama.Fore.LIGHTWHITE_EX
  Role         = colorama.Fore.WHITE
  ColHeader    = colorama.Fore.CYAN
  BoolTrue     = colorama.Fore.GREEN
  BoolFalse    = colorama.Fore.RED
  Skip         = colorama.Fore.WHITE
  Dot          = colorama.Style.DIM + colorama.Fore.WHITE
  TrustEntity  = colorama.Fore.LIGHTYELLOW_EX
  Default      = Info

# Defines a color for some specific known values.
_color_map = {
  True:     Color.BoolTrue,
  False:    Color.BoolFalse,
  '<skip>': Color.Skip,
  '.':      Color.Dot,
}

# Global output text colorization object.
_colorizer = Colorize(_color_map, Color.Default)

# Just a code readability aid.
def Print(insie, color = None, **kwargs):
  print(_colorizer.Colorize(insie, color), **kwargs)

# Just a code readability aid.
def Write(insie, color = None):
  sys.stdout.write(_colorizer.Colorize(insie, color))



########################################################################################################################
# Functions
########################################################################################################################

def GetLocalTimeZoneOffset():
  """Ex: 'UTC-06:00'"""

  ts = time.time()
  dt_local = datetime.fromtimestamp(ts)
  dt_utc = datetime.utcfromtimestamp(ts)
  utc_offset_seconds = (dt_local - dt_utc).total_seconds()
  td = timedelta(seconds=utc_offset_seconds)
  tz = timezone(offset=td)

  return tz



def GetCurrentDateTimeString():
  """Ex: 'Mon Feb 28 16:05:10 2022 (UTC-06:00)'"""

  tz = GetLocalTimeZoneOffset()
  return datetime.now().strftime("%c") + ' (' + str(tz) + ')'



def SimulatePrincipalPolicy(iam, arn, actions, resources):
  """Wrap call to IAM SimulatePrincipalPolicy API."""

  # A single call to IAM SimulatePrincipalPolicy cannot check both the iam:PassRole and iam:AssumeRole actions,
  # as according to the error message they "require different authorization information". So, detect this case
  # and scatter/gather.
  if all(a in actions for a in IAM_ROLE_ACTIONS):

    result = any([SimulatePrincipalPolicy(iam, arn, [a], resources) for a in IAM_ROLE_ACTIONS])
    non_iam_role_actions = [a for a in actions if a not in IAM_ROLE_ACTIONS]
    result = any([result, SimulatePrincipalPolicy(iam, arn, non_iam_role_actions, resources)])

  else:

    # Checks every combination of [actions] and [resources].
    rsp = iam.simulate_principal_policy(
      PolicySourceArn=arn,
      ActionNames=actions,
      ResourceArns=resources
    )

    # Any action allowed for any resource is considered 'allowed' for our purposes.
    result = any([(r['EvalDecision'] == 'allowed') for r in rsp['EvaluationResults']])

  return result



def StatementAllowsAssumeRoleForAwsPrincipal(s):
  """Does the given statement allow sts:AssumeRole for the 'AWS' principal?"""

  result = s['Effect'] == 'Allow' and s['Action'] == 'sts:AssumeRole' and 'AWS' in s['Principal']

  return result



def PrintRoleTrustPolicyInfo(role):
  """Debugging aid."""

  o = role['RoleName'] + " Trust Policy:\n"

  for s in role['AssumeRolePolicyDocument']['Statement']:
    o += "  " + s['Effect'] + " " + s['Action'] + " by " + str(s['Principal'])
    if 'Condition' in s:
      o += " when " + str(s['Condition'])
    o += "\n"

  Print(o, Color.Dev)



def PrintTable(table):
  """Pretty-print a colorized table."""

  # Make a copy with colorized column headers.
  colorized_table = {}

  for rn in table:
    colorized_table[rn] = {}
    for cn in table[rn]:
      colorized_table[rn][_colorizer.Colorize(cn, Color.ColHeader)] = table[rn][cn]

  # Use pandas to format the table, colorizing the elements along the way.
  df = pandas.DataFrame(colorized_table).T.applymap(_colorizer.Colorize)

  print(df)



def CheckParam(p, name, location):
  """Check an input parameter ('None', empty, all whitespace, non-printable characters, ...)"""

  if p is None or p == '' or p.isspace():
    raise Exception("Empty '" + name + "' value found in '" + location + "'.")

  if not p.isprintable():
    raise Exception("Invalid '" + name + "' value found in '" + location + "': '" + p + "'")



########################################################################################################################
# Main Script
########################################################################################################################

def main():

  #
  # Parse Command Line Arguments
  #

  parser = argparse.ArgumentParser(
    description = 'Discover AWS IAM identities (users and roles) with specified access to specified resources.')

  parser.add_argument(
    'parameter_file',
    help = 'JSON format file containing ACTIONS and RESOURCES to check.')

  parser.add_argument(
    '--aws-profile',
    help = 'Name of AWS profile to use for AWS API calls.')

  parser.add_argument(
    '--disable-colors',
    action = 'store_true',
    help = 'Disable output colorization.')

  parser.add_argument(
    '--disable-skip',
    action = 'store_true',
    help = 'Disable skipping non-essential discovery.')

  parser.add_argument(
    '--dev-max-roles',
    type = int,
    help = 'Truncate number of roles examined to expedite development cycles.')

  args = parser.parse_args()

  if args.disable_colors:
    _colorizer.Enabled = False

  #
  # Load Parameter File
  #

  try:

    with open(args.parameter_file, "r") as f:
      params = json.load(f)

    if 'ACTIONS' not in params:
      raise Exception("Required parameter 'ACTIONS' not found in '" + args.parameter_file + "'.")

    [CheckParam(p, 'ACTIONS', args.parameter_file) for p in params['ACTIONS']]

    if 'RESOURCES' not in params:
      raise Exception("Required parameter 'RESOURCES' not found in '" + args.parameter_file + "'.")

    [CheckParam(p, 'RESOURCES', args.parameter_file) for p in params['RESOURCES']]

  except Exception as err:

    Print(err, Color.Error)
    exit()

  setattr(args, 'actions', params['ACTIONS'])
  setattr(args, 'resources', params['RESOURCES'])

  #
  # Init
  #

  # Boto3 is a Python SDK for accessing AWS APIs.
  boto3.setup_default_session(profile_name = args.aws_profile)
  iam = boto3.client('iam')

  # Pandas is used to format output as a table.
  pandas.set_option('colheader_justify', 'center')

  #
  # Intro
  #

  Print('')
  Print('Current Time:')
  Print('  ' + GetCurrentDateTimeString())
  Print('')
  Print('Input Parameters:')
  Print('  Account:   ' + boto3.client('sts').get_caller_identity().get('Account'))
  Print('  Actions:   ' + str(args.actions))
  Print('  Resources: ' + str(args.resources))
  Print('')

  all_roles = []
  role_results = {}
  allowed_roles = set()
  all_users = []
  user_results = {}

  #
  # All the Real Work...
  #

  Print("Retrieving list of IAM Roles...", end=''),

  for rsp in iam.get_paginator('list_roles').paginate():
    for role in rsp['Roles']:
      all_roles.append(role)

  Print("(Found " + str(len(all_roles)) + ")")

  if args.dev_max_roles:
    msg = "  Truncating to --dev-max-roles = " + str(args.dev_max_roles)
    Print(msg, Color.Dev)
    del all_roles[args.dev_max_roles:]



  Print('')
  Print("Checking each IAM Role for " + str(args.actions), end='')

  for role in all_roles:

    role_results[role['RoleName']] = {}
    result = SimulatePrincipalPolicy(iam, role['Arn'], args.actions, args.resources)
    role_results[role['RoleName']]['DIRECT'] = result
    if result:
      allowed_roles.add(role['Arn'])
    Write(".")
    sys.stdout.flush()



  Print('')
  Print("Checking each IAM Role for " + str(IAM_POLICY_ACTIONS), end=''),

  for role in all_roles:

    result = SimulatePrincipalPolicy(iam, role['Arn'], IAM_POLICY_ACTIONS, ['*'])
    role_results[role['RoleName']]['IAM_API'] = result
    if result:
      allowed_roles.add(role['Arn'])
    Write(".")
    sys.stdout.flush()



  Print('')
  Print("Checking each IAM Role for " + str(IAM_ROLE_ACTIONS), end=''),

  # Must repeat until no additional roles with access are discovered.

  allowed_roles_cnt = 0

  # While the allowed_roles count increased on the last iteration...
  while allowed_roles_cnt != len(allowed_roles):

    if allowed_roles_cnt != 0:
      Print("Rechecking...")

    allowed_roles_cnt = len(allowed_roles)

    for role in all_roles:

      if not args.disable_skip and role['Arn'] in allowed_roles:
        # Skip checking roles that are already known to have access (saves time).
        role_results[role['RoleName']]['IAM_ROLE'] = '<skip>'
      else:
        result = SimulatePrincipalPolicy(iam, role['Arn'], IAM_ROLE_ACTIONS, list(allowed_roles))
        role_results[role['RoleName']]['IAM_ROLE'] = result
        if result:
          allowed_roles.add(role['Arn'])
        Write(".")
        sys.stdout.flush()



  Print('')
  Print("Checking Trusted Entities for each IAM Role with access", end=''),

  for role in all_roles:

    if not args.disable_skip and role['Arn'] not in allowed_roles:
      # Skip checking roles that do not have access (saves time).
      role_results[role['RoleName']]['TRUSTS'] = '<skip>'
    else:
      rs = role['AssumeRolePolicyDocument']['Statement']
      result = any([(StatementAllowsAssumeRoleForAwsPrincipal(s)) for s in rs])
      role_results[role['RoleName']]['TRUSTS'] = result
    Write(".")
    sys.stdout.flush()



  Print('')
  Print('')
  Print("IAM Role Results:", Color.Section)
  Print('')

  PrintTable(role_results)



  Print('')
  Print("Retrieving list of IAM Users...", end=''),

  for rsp in iam.get_paginator('list_users').paginate():
    for user in rsp['Users']:
      all_users.append(user)

  Print("(Found " + str(len(all_users)) + ")")



  Print('')
  Print("Checking each IAM User for " + str(args.actions), end='')

  for user in all_users:

    user_results[user['UserName']] = {}
    result = SimulatePrincipalPolicy(iam, user['Arn'], args.actions, args.resources)
    user_results[user['UserName']]['DIRECT'] = result
    Write(".")
    sys.stdout.flush()



  Print('')
  Print("Checking each IAM User for " + str(IAM_POLICY_ACTIONS), end=''),

  for user in all_users:

    result = SimulatePrincipalPolicy(iam, user['Arn'], IAM_POLICY_ACTIONS, ['*'])
    user_results[user['UserName']]['IAM_API'] = result
    Write(".")
    sys.stdout.flush()



  Print('')
  Print("Checking each IAM User for " + str(IAM_ROLE_ACTIONS), end=''),

  for user in all_users:

    result = SimulatePrincipalPolicy(iam, user['Arn'], IAM_ROLE_ACTIONS, list(allowed_roles))
    user_results[user['UserName']]['IAM_ROLE'] = result
    Write(".")
    sys.stdout.flush()



  Print('')
  Print('')
  Print("IAM User Results:", Color.Section)
  Print('')

  PrintTable(user_results)



  Print('')
  Print('')
  Print("IAM Role External Account Trust Entities:", Color.Section)
  Print('')

  for role in all_roles:

    if role['Arn'] in allowed_roles and role_results[role['RoleName']]['TRUSTS']:
      Print(role['RoleName'], Color.Role, end='')
      Print(" (" + role['Arn'] + ")", Color.Info)

      for s in role['AssumeRolePolicyDocument']['Statement']:

        if StatementAllowsAssumeRoleForAwsPrincipal(s):
          Print("  " + s['Principal']['AWS'].removeprefix("arn:aws:iam::"), Color.TrustEntity)



########################################################################################################################
# See: https://docs.python.org/3/library/__main__.html#idiomatic-usage
########################################################################################################################

if __name__ == '__main__':
  sys.exit(main())
