# Analyst Tool
# Author: Jeremy Wiedner (@JeremyWiedner)
# License:
# Purpose:  To help automate some of an analyst workflow as much as possible.  Simply copy an Domain, Hash, IP Address, Port # or Windows Event ID and the main script will pull the 

import datetime
import ipaddress
import json
import re
import requests
import time
import win32clipboard
import validators
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from ipwhois import IPWhois
from configparser import ConfigParser

# Regex to be used in the main loop of the Jupyter Notebook
hash_validation_regex = '^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$'
port_wid_validation_regex = '^[0-9]{1,5}$'

# Other Regex
# Regex to pull the created date out of whois info for a domain
creation_date_regex = 'created: ([0-9T:-]+)'

# List of dictionaires countataining the Country name and codes from https://www.iban.com/country-codes
countries = [{'Country': 'Afghanistan', 'Alpha-2 code': 'AF', 'Alpha-3 code': 'AFG', 'Numeric': 4}, {'Country': 'Åland Islands', 'Alpha-2 code': 'AX', 'Alpha-3 code': 'ALA', 'Numeric': 248}, {'Country': 'Albania', 'Alpha-2 code': 'AL', 'Alpha-3 code': 'ALB', 'Numeric': 8}, {'Country': 'Algeria', 'Alpha-2 code': 'DZ', 'Alpha-3 code': 'DZA', 'Numeric': 12}, {'Country': 'American Samoa', 'Alpha-2 code': 'AS', 'Alpha-3 code': 'ASM', 'Numeric': 16}, {'Country': 'Andorra', 'Alpha-2 code': 'AD', 'Alpha-3 code': 'AND', 'Numeric': 20}, {'Country': 'Angola', 'Alpha-2 code': 'AO', 'Alpha-3 code': 'AGO', 'Numeric': 24}, {'Country': 'Anguilla', 'Alpha-2 code': 'AI', 'Alpha-3 code': 'AIA', 'Numeric': 660}, {'Country': 'Antarctica', 'Alpha-2 code': 'AQ', 'Alpha-3 code': 'ATA', 'Numeric': 10}, {'Country': 'Antigua and Barbuda', 'Alpha-2 code': 'AG', 'Alpha-3 code': 'ATG', 'Numeric': 28}, {'Country': 'Argentina', 'Alpha-2 code': 'AR', 'Alpha-3 code': 'ARG', 'Numeric': 32}, {'Country': 'Armenia', 'Alpha-2 code': 'AM', 'Alpha-3 code': 'ARM', 'Numeric': 51}, {'Country': 'Aruba', 'Alpha-2 code': 'AW', 'Alpha-3 code': 'ABW', 'Numeric': 533}, {'Country': 'Australia', 'Alpha-2 code': 'AU', 'Alpha-3 code': 'AUS', 'Numeric': 36}, {'Country': 'Austria', 'Alpha-2 code': 'AT', 'Alpha-3 code': 'AUT', 'Numeric': 40}, {'Country': 'Azerbaijan', 'Alpha-2 code': 'AZ', 'Alpha-3 code': 'AZE', 'Numeric': 31}, {'Country': 'Bahamas (the)', 'Alpha-2 code': 'BS', 'Alpha-3 code': 'BHS', 'Numeric': 44}, {'Country': 'Bahrain', 'Alpha-2 code': 'BH', 'Alpha-3 code': 'BHR', 'Numeric': 48}, {'Country': 'Bangladesh', 'Alpha-2 code': 'BD', 'Alpha-3 code': 'BGD', 'Numeric': 50}, {'Country': 'Barbados', 'Alpha-2 code': 'BB', 'Alpha-3 code': 'BRB', 'Numeric': 52}, {'Country': 'Belarus', 'Alpha-2 code': 'BY', 'Alpha-3 code': 'BLR', 'Numeric': 112}, {'Country': 'Belgium', 'Alpha-2 code': 'BE', 'Alpha-3 code': 'BEL', 'Numeric': 56}, {'Country': 'Belize', 'Alpha-2 code': 'BZ', 'Alpha-3 code': 'BLZ', 'Numeric': 84}, {'Country': 'Benin', 'Alpha-2 code': 'BJ', 'Alpha-3 code': 'BEN', 'Numeric': 204}, {'Country': 'Bermuda', 'Alpha-2 code': 'BM', 'Alpha-3 code': 'BMU', 'Numeric': 60}, {'Country': 'Bhutan', 'Alpha-2 code': 'BT', 'Alpha-3 code': 'BTN', 'Numeric': 64}, {'Country': 'Bolivia (Plurinational State of)', 'Alpha-2 code': 'BO', 'Alpha-3 code': 'BOL', 'Numeric': 68}, {'Country': 'Bonaire, Sint Eustatius and Saba', 'Alpha-2 code': 'BQ', 'Alpha-3 code': 'BES', 'Numeric': 535}, {'Country': 'Bosnia and Herzegovina', 'Alpha-2 code': 'BA', 'Alpha-3 code': 'BIH', 'Numeric': 70}, {'Country': 'Botswana', 'Alpha-2 code': 'BW', 'Alpha-3 code': 'BWA', 'Numeric': 72}, {'Country': 'Bouvet Island', 'Alpha-2 code': 'BV', 'Alpha-3 code': 'BVT', 'Numeric': 74}, {'Country': 'Brazil', 'Alpha-2 code': 'BR', 'Alpha-3 code': 'BRA', 'Numeric': 76}, {'Country': 'British Indian Ocean Territory (the)', 'Alpha-2 code': 'IO', 'Alpha-3 code': 'IOT', 'Numeric': 86}, {'Country': 'Brunei Darussalam', 'Alpha-2 code': 'BN', 'Alpha-3 code': 'BRN', 'Numeric': 96}, {'Country': 'Bulgaria', 'Alpha-2 code': 'BG', 'Alpha-3 code': 'BGR', 'Numeric': 100}, {'Country': 'Burkina Faso', 'Alpha-2 code': 'BF', 'Alpha-3 code': 'BFA', 'Numeric': 854}, {'Country': 'Burundi', 'Alpha-2 code': 'BI', 'Alpha-3 code': 'BDI', 'Numeric': 108}, {'Country': 'Cabo Verde', 'Alpha-2 code': 'CV', 'Alpha-3 code': 'CPV', 'Numeric': 132}, {'Country': 'Cambodia', 'Alpha-2 code': 'KH', 'Alpha-3 code': 'KHM', 'Numeric': 116}, {'Country': 'Cameroon', 'Alpha-2 code': 'CM', 'Alpha-3 code': 'CMR', 'Numeric': 120}, {'Country': 'Canada', 'Alpha-2 code': 'CA', 'Alpha-3 code': 'CAN', 'Numeric': 124}, {'Country': 'Cayman Islands (the)', 'Alpha-2 code': 'KY', 'Alpha-3 code': 'CYM', 'Numeric': 136}, {'Country': 'Central African Republic (the)', 'Alpha-2 code': 'CF', 'Alpha-3 code': 'CAF', 'Numeric': 140}, {'Country': 'Chad', 'Alpha-2 code': 'TD', 'Alpha-3 code': 'TCD', 'Numeric': 148}, {'Country': 'Chile', 'Alpha-2 code': 'CL', 'Alpha-3 code': 'CHL', 'Numeric': 152}, {'Country': 'China', 'Alpha-2 code': 'CN', 'Alpha-3 code': 'CHN', 'Numeric': 156}, {'Country': 'Christmas Island', 'Alpha-2 code': 'CX', 'Alpha-3 code': 'CXR', 'Numeric': 162}, {'Country': 'Cocos (Keeling) Islands (the)', 'Alpha-2 code': 'CC', 'Alpha-3 code': 'CCK', 'Numeric': 166}, {'Country': 'Colombia', 'Alpha-2 code': 'CO', 'Alpha-3 code': 'COL', 'Numeric': 170}, {'Country': 'Comoros (the)', 'Alpha-2 code': 'KM', 'Alpha-3 code': 'COM', 'Numeric': 174}, {'Country': 'Congo (the Democratic Republic of the)', 'Alpha-2 code': 'CD', 'Alpha-3 code': 'COD', 'Numeric': 180}, {'Country': 'Congo (the)', 'Alpha-2 code': 'CG', 'Alpha-3 code': 'COG', 'Numeric': 178}, {'Country': 'Cook Islands (the)', 'Alpha-2 code': 'CK', 'Alpha-3 code': 'COK', 'Numeric': 184}, {'Country': 'Costa Rica', 'Alpha-2 code': 'CR', 'Alpha-3 code': 'CRI', 'Numeric': 188}, {'Country': "Côte d'Ivoire", 'Alpha-2 code': 'CI', 'Alpha-3 code': 'CIV', 'Numeric': 384}, {'Country': 'Croatia', 'Alpha-2 code': 'HR', 'Alpha-3 code': 'HRV', 'Numeric': 191}, {'Country': 'Cuba', 'Alpha-2 code': 'CU', 'Alpha-3 code': 'CUB', 'Numeric': 192}, {'Country': 'Curaçao', 'Alpha-2 code': 'CW', 'Alpha-3 code': 'CUW', 'Numeric': 531}, {'Country': 'Cyprus', 'Alpha-2 code': 'CY', 'Alpha-3 code': 'CYP', 'Numeric': 196}, {'Country': 'Czechia', 'Alpha-2 code': 'CZ', 'Alpha-3 code': 'CZE', 'Numeric': 203}, {'Country': 'Denmark', 'Alpha-2 code': 'DK', 'Alpha-3 code': 'DNK', 'Numeric': 208}, {'Country': 'Djibouti', 'Alpha-2 code': 'DJ', 'Alpha-3 code': 'DJI', 'Numeric': 262}, {'Country': 'Dominica', 'Alpha-2 code': 'DM', 'Alpha-3 code': 'DMA', 'Numeric': 212}, {'Country': 'Dominican Republic (the)', 'Alpha-2 code': 'DO', 'Alpha-3 code': 'DOM', 'Numeric': 214}, {'Country': 'Ecuador', 'Alpha-2 code': 'EC', 'Alpha-3 code': 'ECU', 'Numeric': 218}, {'Country': 'Egypt', 'Alpha-2 code': 'EG', 'Alpha-3 code': 'EGY', 'Numeric': 818}, {'Country': 'El Salvador', 'Alpha-2 code': 'SV', 'Alpha-3 code': 'SLV', 'Numeric': 222}, {'Country': 'Equatorial Guinea', 'Alpha-2 code': 'GQ', 'Alpha-3 code': 'GNQ', 'Numeric': 226}, {'Country': 'Eritrea', 'Alpha-2 code': 'ER', 'Alpha-3 code': 'ERI', 'Numeric': 232}, {'Country': 'Estonia', 'Alpha-2 code': 'EE', 'Alpha-3 code': 'EST', 'Numeric': 233}, {'Country': 'Eswatini', 'Alpha-2 code': 'SZ', 'Alpha-3 code': 'SWZ', 'Numeric': 748}, {'Country': 'Ethiopia', 'Alpha-2 code': 'ET', 'Alpha-3 code': 'ETH', 'Numeric': 231}, {'Country': 'Falkland Islands (the) [Malvinas]', 'Alpha-2 code': 'FK', 'Alpha-3 code': 'FLK', 'Numeric': 238}, {'Country': 'Faroe Islands (the)', 'Alpha-2 code': 'FO', 'Alpha-3 code': 'FRO', 'Numeric': 234}, {'Country': 'Fiji', 'Alpha-2 code': 'FJ', 'Alpha-3 code': 'FJI', 'Numeric': 242}, {'Country': 'Finland', 'Alpha-2 code': 'FI', 'Alpha-3 code': 'FIN', 'Numeric': 246}, {'Country': 'France', 'Alpha-2 code': 'FR', 'Alpha-3 code': 'FRA', 'Numeric': 250}, {'Country': 'French Guiana', 'Alpha-2 code': 'GF', 'Alpha-3 code': 'GUF', 'Numeric': 254}, {'Country': 'French Polynesia', 'Alpha-2 code': 'PF', 'Alpha-3 code': 'PYF', 'Numeric': 258}, {'Country': 'French Southern Territories (the)', 'Alpha-2 code': 'TF', 'Alpha-3 code': 'ATF', 'Numeric': 260}, {'Country': 'Gabon', 'Alpha-2 code': 'GA', 'Alpha-3 code': 'GAB', 'Numeric': 266}, {'Country': 'Gambia (the)', 'Alpha-2 code': 'GM', 'Alpha-3 code': 'GMB', 'Numeric': 270}, {'Country': 'Georgia', 'Alpha-2 code': 'GE', 'Alpha-3 code': 'GEO', 'Numeric': 268}, {'Country': 'Germany', 'Alpha-2 code': 'DE', 'Alpha-3 code': 'DEU', 'Numeric': 276}, {'Country': 'Ghana', 'Alpha-2 code': 'GH', 'Alpha-3 code': 'GHA', 'Numeric': 288}, {'Country': 'Gibraltar', 'Alpha-2 code': 'GI', 'Alpha-3 code': 'GIB', 'Numeric': 292}, {'Country': 'Greece', 'Alpha-2 code': 'GR', 'Alpha-3 code': 'GRC', 'Numeric': 300}, {'Country': 'Greenland', 'Alpha-2 code': 'GL', 'Alpha-3 code': 'GRL', 'Numeric': 304}, {'Country': 'Grenada', 'Alpha-2 code': 'GD', 'Alpha-3 code': 'GRD', 'Numeric': 308}, {'Country': 'Guadeloupe', 'Alpha-2 code': 'GP', 'Alpha-3 code': 'GLP', 'Numeric': 312}, {'Country': 'Guam', 'Alpha-2 code': 'GU', 'Alpha-3 code': 'GUM', 'Numeric': 316}, {'Country': 'Guatemala', 'Alpha-2 code': 'GT', 'Alpha-3 code': 'GTM', 'Numeric': 320}, {'Country': 'Guernsey', 'Alpha-2 code': 'GG', 'Alpha-3 code': 'GGY', 'Numeric': 831}, {'Country': 'Guinea', 'Alpha-2 code': 'GN', 'Alpha-3 code': 'GIN', 'Numeric': 324}, {'Country': 'Guinea-Bissau', 'Alpha-2 code': 'GW', 'Alpha-3 code': 'GNB', 'Numeric': 624}, {'Country': 'Guyana', 'Alpha-2 code': 'GY', 'Alpha-3 code': 'GUY', 'Numeric': 328}, {'Country': 'Haiti', 'Alpha-2 code': 'HT', 'Alpha-3 code': 'HTI', 'Numeric': 332}, {'Country': 'Heard Island and McDonald Islands', 'Alpha-2 code': 'HM', 'Alpha-3 code': 'HMD', 'Numeric': 334}, {'Country': 'Holy See (the)', 'Alpha-2 code': 'VA', 'Alpha-3 code': 'VAT', 'Numeric': 336}, {'Country': 'Honduras', 'Alpha-2 code': 'HN', 'Alpha-3 code': 'HND', 'Numeric': 340}, {'Country': 'Hong Kong', 'Alpha-2 code': 'HK', 'Alpha-3 code': 'HKG', 'Numeric': 344}, {'Country': 'Hungary', 'Alpha-2 code': 'HU', 'Alpha-3 code': 'HUN', 'Numeric': 348}, {'Country': 'Iceland', 'Alpha-2 code': 'IS', 'Alpha-3 code': 'ISL', 'Numeric': 352}, {'Country': 'India', 'Alpha-2 code': 'IN', 'Alpha-3 code': 'IND', 'Numeric': 356}, {'Country': 'Indonesia', 'Alpha-2 code': 'ID', 'Alpha-3 code': 'IDN', 'Numeric': 360}, {'Country': 'Iran (Islamic Republic of)', 'Alpha-2 code': 'IR', 'Alpha-3 code': 'IRN', 'Numeric': 364}, {'Country': 'Iraq', 'Alpha-2 code': 'IQ', 'Alpha-3 code': 'IRQ', 'Numeric': 368}, {'Country': 'Ireland', 'Alpha-2 code': 'IE', 'Alpha-3 code': 'IRL', 'Numeric': 372}, {'Country': 'Isle of Man', 'Alpha-2 code': 'IM', 'Alpha-3 code': 'IMN', 'Numeric': 833}, {'Country': 'Israel', 'Alpha-2 code': 'IL', 'Alpha-3 code': 'ISR', 'Numeric': 376}, {'Country': 'Italy', 'Alpha-2 code': 'IT', 'Alpha-3 code': 'ITA', 'Numeric': 380}, {'Country': 'Jamaica', 'Alpha-2 code': 'JM', 'Alpha-3 code': 'JAM', 'Numeric': 388}, {'Country': 'Japan', 'Alpha-2 code': 'JP', 'Alpha-3 code': 'JPN', 'Numeric': 392}, {'Country': 'Jersey', 'Alpha-2 code': 'JE', 'Alpha-3 code': 'JEY', 'Numeric': 832}, {'Country': 'Jordan', 'Alpha-2 code': 'JO', 'Alpha-3 code': 'JOR', 'Numeric': 400}, {'Country': 'Kazakhstan', 'Alpha-2 code': 'KZ', 'Alpha-3 code': 'KAZ', 'Numeric': 398}, {'Country': 'Kenya', 'Alpha-2 code': 'KE', 'Alpha-3 code': 'KEN', 'Numeric': 404}, {'Country': 'Kiribati', 'Alpha-2 code': 'KI', 'Alpha-3 code': 'KIR', 'Numeric': 296}, {'Country': "Korea (the Democratic People's Republic of)", 'Alpha-2 code': 'KP', 'Alpha-3 code': 'PRK', 'Numeric': 408}, {'Country': 'Korea (the Republic of)', 'Alpha-2 code': 'KR', 'Alpha-3 code': 'KOR', 'Numeric': 410}, {'Country': 'Kuwait', 'Alpha-2 code': 'KW', 'Alpha-3 code': 'KWT', 'Numeric': 414}, {'Country': 'Kyrgyzstan', 'Alpha-2 code': 'KG', 'Alpha-3 code': 'KGZ', 'Numeric': 417}, {'Country': "Lao People's Democratic Republic (the)", 'Alpha-2 code': 'LA', 'Alpha-3 code': 'LAO', 'Numeric': 418}, {'Country': 'Latvia', 'Alpha-2 code': 'LV', 'Alpha-3 code': 'LVA', 'Numeric': 428}, {'Country': 'Lebanon', 'Alpha-2 code': 'LB', 'Alpha-3 code': 'LBN', 'Numeric': 422}, {'Country': 'Lesotho', 'Alpha-2 code': 'LS', 'Alpha-3 code': 'LSO', 'Numeric': 426}, {'Country': 'Liberia', 'Alpha-2 code': 'LR', 'Alpha-3 code': 'LBR', 'Numeric': 430}, {'Country': 'Libya', 'Alpha-2 code': 'LY', 'Alpha-3 code': 'LBY', 'Numeric': 434}, {'Country': 'Liechtenstein', 'Alpha-2 code': 'LI', 'Alpha-3 code': 'LIE', 'Numeric': 438}, {'Country': 'Lithuania', 'Alpha-2 code': 'LT', 'Alpha-3 code': 'LTU', 'Numeric': 440}, {'Country': 'Luxembourg', 'Alpha-2 code': 'LU', 'Alpha-3 code': 'LUX', 'Numeric': 442}, {'Country': 'Macao', 'Alpha-2 code': 'MO', 'Alpha-3 code': 'MAC', 'Numeric': 446}, {'Country': 'Republic of North Macedonia', 'Alpha-2 code': 'MK', 'Alpha-3 code': 'MKD', 'Numeric': 807}, {'Country': 'Madagascar', 'Alpha-2 code': 'MG', 'Alpha-3 code': 'MDG', 'Numeric': 450}, {'Country': 'Malawi', 'Alpha-2 code': 'MW', 'Alpha-3 code': 'MWI', 'Numeric': 454}, {'Country': 'Malaysia', 'Alpha-2 code': 'MY', 'Alpha-3 code': 'MYS', 'Numeric': 458}, {'Country': 'Maldives', 'Alpha-2 code': 'MV', 'Alpha-3 code': 'MDV', 'Numeric': 462}, {'Country': 'Mali', 'Alpha-2 code': 'ML', 'Alpha-3 code': 'MLI', 'Numeric': 466}, {'Country': 'Malta', 'Alpha-2 code': 'MT', 'Alpha-3 code': 'MLT', 'Numeric': 470}, {'Country': 'Marshall Islands (the)', 'Alpha-2 code': 'MH', 'Alpha-3 code': 'MHL', 'Numeric': 584}, {'Country': 'Martinique', 'Alpha-2 code': 'MQ', 'Alpha-3 code': 'MTQ', 'Numeric': 474}, {'Country': 'Mauritania', 'Alpha-2 code': 'MR', 'Alpha-3 code': 'MRT', 'Numeric': 478}, {'Country': 'Mauritius', 'Alpha-2 code': 'MU', 'Alpha-3 code': 'MUS', 'Numeric': 480}, {'Country': 'Mayotte', 'Alpha-2 code': 'YT', 'Alpha-3 code': 'MYT', 'Numeric': 175}, {'Country': 'Mexico', 'Alpha-2 code': 'MX', 'Alpha-3 code': 'MEX', 'Numeric': 484}, {'Country': 'Micronesia (Federated States of)', 'Alpha-2 code': 'FM', 'Alpha-3 code': 'FSM', 'Numeric': 583}, {'Country': 'Moldova (the Republic of)', 'Alpha-2 code': 'MD', 'Alpha-3 code': 'MDA', 'Numeric': 498}, {'Country': 'Monaco', 'Alpha-2 code': 'MC', 'Alpha-3 code': 'MCO', 'Numeric': 492}, {'Country': 'Mongolia', 'Alpha-2 code': 'MN', 'Alpha-3 code': 'MNG', 'Numeric': 496}, {'Country': 'Montenegro', 'Alpha-2 code': 'ME', 'Alpha-3 code': 'MNE', 'Numeric': 499}, {'Country': 'Montserrat', 'Alpha-2 code': 'MS', 'Alpha-3 code': 'MSR', 'Numeric': 500}, {'Country': 'Morocco', 'Alpha-2 code': 'MA', 'Alpha-3 code': 'MAR', 'Numeric': 504}, {'Country': 'Mozambique', 'Alpha-2 code': 'MZ', 'Alpha-3 code': 'MOZ', 'Numeric': 508}, {'Country': 'Myanmar', 'Alpha-2 code': 'MM', 'Alpha-3 code': 'MMR', 'Numeric': 104}, {'Country': 'Namibia', 'Alpha-2 code': 'NA', 'Alpha-3 code': 'NAM', 'Numeric': 516}, {'Country': 'Nauru', 'Alpha-2 code': 'NR', 'Alpha-3 code': 'NRU', 'Numeric': 520}, {'Country': 'Nepal', 'Alpha-2 code': 'NP', 'Alpha-3 code': 'NPL', 'Numeric': 524}, {'Country': 'Netherlands (the)', 'Alpha-2 code': 'NL', 'Alpha-3 code': 'NLD', 'Numeric': 528}, {'Country': 'New Caledonia', 'Alpha-2 code': 'NC', 'Alpha-3 code': 'NCL', 'Numeric': 540}, {'Country': 'New Zealand', 'Alpha-2 code': 'NZ', 'Alpha-3 code': 'NZL', 'Numeric': 554}, {'Country': 'Nicaragua', 'Alpha-2 code': 'NI', 'Alpha-3 code': 'NIC', 'Numeric': 558}, {'Country': 'Niger (the)', 'Alpha-2 code': 'NE', 'Alpha-3 code': 'NER', 'Numeric': 562}, {'Country': 'Nigeria', 'Alpha-2 code': 'NG', 'Alpha-3 code': 'NGA', 'Numeric': 566}, {'Country': 'Niue', 'Alpha-2 code': 'NU', 'Alpha-3 code': 'NIU', 'Numeric': 570}, {'Country': 'Norfolk Island', 'Alpha-2 code': 'NF', 'Alpha-3 code': 'NFK', 'Numeric': 574}, {'Country': 'Northern Mariana Islands (the)', 'Alpha-2 code': 'MP', 'Alpha-3 code': 'MNP', 'Numeric': 580}, {'Country': 'Norway', 'Alpha-2 code': 'NO', 'Alpha-3 code': 'NOR', 'Numeric': 578}, {'Country': 'Oman', 'Alpha-2 code': 'OM', 'Alpha-3 code': 'OMN', 'Numeric': 512}, {'Country': 'Pakistan', 'Alpha-2 code': 'PK', 'Alpha-3 code': 'PAK', 'Numeric': 586}, {'Country': 'Palau', 'Alpha-2 code': 'PW', 'Alpha-3 code': 'PLW', 'Numeric': 585}, {'Country': 'Palestine, State of', 'Alpha-2 code': 'PS', 'Alpha-3 code': 'PSE', 'Numeric': 275}, {'Country': 'Panama', 'Alpha-2 code': 'PA', 'Alpha-3 code': 'PAN', 'Numeric': 591}, {'Country': 'Papua New Guinea', 'Alpha-2 code': 'PG', 'Alpha-3 code': 'PNG', 'Numeric': 598}, {'Country': 'Paraguay', 'Alpha-2 code': 'PY', 'Alpha-3 code': 'PRY', 'Numeric': 600}, {'Country': 'Peru', 'Alpha-2 code': 'PE', 'Alpha-3 code': 'PER', 'Numeric': 604}, {'Country': 'Philippines (the)', 'Alpha-2 code': 'PH', 'Alpha-3 code': 'PHL', 'Numeric': 608}, {'Country': 'Pitcairn', 'Alpha-2 code': 'PN', 'Alpha-3 code': 'PCN', 'Numeric': 612}, {'Country': 'Poland', 'Alpha-2 code': 'PL', 'Alpha-3 code': 'POL', 'Numeric': 616}, {'Country': 'Portugal', 'Alpha-2 code': 'PT', 'Alpha-3 code': 'PRT', 'Numeric': 620}, {'Country': 'Puerto Rico', 'Alpha-2 code': 'PR', 'Alpha-3 code': 'PRI', 'Numeric': 630}, {'Country': 'Qatar', 'Alpha-2 code': 'QA', 'Alpha-3 code': 'QAT', 'Numeric': 634}, {'Country': 'Réunion', 'Alpha-2 code': 'RE', 'Alpha-3 code': 'REU', 'Numeric': 638}, {'Country': 'Romania', 'Alpha-2 code': 'RO', 'Alpha-3 code': 'ROU', 'Numeric': 642}, {'Country': 'Russian Federation (the)', 'Alpha-2 code': 'RU', 'Alpha-3 code': 'RUS', 'Numeric': 643}, {'Country': 'Rwanda', 'Alpha-2 code': 'RW', 'Alpha-3 code': 'RWA', 'Numeric': 646}, {'Country': 'Saint Barthélemy', 'Alpha-2 code': 'BL', 'Alpha-3 code': 'BLM', 'Numeric': 652}, {'Country': 'Saint Helena, Ascension and Tristan da Cunha', 'Alpha-2 code': 'SH', 'Alpha-3 code': 'SHN', 'Numeric': 654}, {'Country': 'Saint Kitts and Nevis', 'Alpha-2 code': 'KN', 'Alpha-3 code': 'KNA', 'Numeric': 659}, {'Country': 'Saint Lucia', 'Alpha-2 code': 'LC', 'Alpha-3 code': 'LCA', 'Numeric': 662}, {'Country': 'Saint Martin (French part)', 'Alpha-2 code': 'MF', 'Alpha-3 code': 'MAF', 'Numeric': 663}, {'Country': 'Saint Pierre and Miquelon', 'Alpha-2 code': 'PM', 'Alpha-3 code': 'SPM', 'Numeric': 666}, {'Country': 'Saint Vincent and the Grenadines', 'Alpha-2 code': 'VC', 'Alpha-3 code': 'VCT', 'Numeric': 670}, {'Country': 'Samoa', 'Alpha-2 code': 'WS', 'Alpha-3 code': 'WSM', 'Numeric': 882}, {'Country': 'San Marino', 'Alpha-2 code': 'SM', 'Alpha-3 code': 'SMR', 'Numeric': 674}, {'Country': 'Sao Tome and Principe', 'Alpha-2 code': 'ST', 'Alpha-3 code': 'STP', 'Numeric': 678}, {'Country': 'Saudi Arabia', 'Alpha-2 code': 'SA', 'Alpha-3 code': 'SAU', 'Numeric': 682}, {'Country': 'Senegal', 'Alpha-2 code': 'SN', 'Alpha-3 code': 'SEN', 'Numeric': 686}, {'Country': 'Serbia', 'Alpha-2 code': 'RS', 'Alpha-3 code': 'SRB', 'Numeric': 688}, {'Country': 'Seychelles', 'Alpha-2 code': 'SC', 'Alpha-3 code': 'SYC', 'Numeric': 690}, {'Country': 'Sierra Leone', 'Alpha-2 code': 'SL', 'Alpha-3 code': 'SLE', 'Numeric': 694}, {'Country': 'Singapore', 'Alpha-2 code': 'SG', 'Alpha-3 code': 'SGP', 'Numeric': 702}, {'Country': 'Sint Maarten (Dutch part)', 'Alpha-2 code': 'SX', 'Alpha-3 code': 'SXM', 'Numeric': 534}, {'Country': 'Slovakia', 'Alpha-2 code': 'SK', 'Alpha-3 code': 'SVK', 'Numeric': 703}, {'Country': 'Slovenia', 'Alpha-2 code': 'SI', 'Alpha-3 code': 'SVN', 'Numeric': 705}, {'Country': 'Solomon Islands', 'Alpha-2 code': 'SB', 'Alpha-3 code': 'SLB', 'Numeric': 90}, {'Country': 'Somalia', 'Alpha-2 code': 'SO', 'Alpha-3 code': 'SOM', 'Numeric': 706}, {'Country': 'South Africa', 'Alpha-2 code': 'ZA', 'Alpha-3 code': 'ZAF', 'Numeric': 710}, {'Country': 'South Georgia and the South Sandwich Islands', 'Alpha-2 code': 'GS', 'Alpha-3 code': 'SGS', 'Numeric': 239}, {'Country': 'South Sudan', 'Alpha-2 code': 'SS', 'Alpha-3 code': 'SSD', 'Numeric': 728}, {'Country': 'Spain', 'Alpha-2 code': 'ES', 'Alpha-3 code': 'ESP', 'Numeric': 724}, {'Country': 'Sri Lanka', 'Alpha-2 code': 'LK', 'Alpha-3 code': 'LKA', 'Numeric': 144}, {'Country': 'Sudan (the)', 'Alpha-2 code': 'SD', 'Alpha-3 code': 'SDN', 'Numeric': 729}, {'Country': 'Suriname', 'Alpha-2 code': 'SR', 'Alpha-3 code': 'SUR', 'Numeric': 740}, {'Country': 'Svalbard and Jan Mayen', 'Alpha-2 code': 'SJ', 'Alpha-3 code': 'SJM', 'Numeric': 744}, {'Country': 'Sweden', 'Alpha-2 code': 'SE', 'Alpha-3 code': 'SWE', 'Numeric': 752}, {'Country': 'Switzerland', 'Alpha-2 code': 'CH', 'Alpha-3 code': 'CHE', 'Numeric': 756}, {'Country': 'Syrian Arab Republic', 'Alpha-2 code': 'SY', 'Alpha-3 code': 'SYR', 'Numeric': 760}, {'Country': 'Taiwan (Province of China)', 'Alpha-2 code': 'TW', 'Alpha-3 code': 'TWN', 'Numeric': 158}, {'Country': 'Tajikistan', 'Alpha-2 code': 'TJ', 'Alpha-3 code': 'TJK', 'Numeric': 762}, {'Country': 'Tanzania, United Republic of', 'Alpha-2 code': 'TZ', 'Alpha-3 code': 'TZA', 'Numeric': 834}, {'Country': 'Thailand', 'Alpha-2 code': 'TH', 'Alpha-3 code': 'THA', 'Numeric': 764}, {'Country': 'Timor-Leste', 'Alpha-2 code': 'TL', 'Alpha-3 code': 'TLS', 'Numeric': 626}, {'Country': 'Togo', 'Alpha-2 code': 'TG', 'Alpha-3 code': 'TGO', 'Numeric': 768}, {'Country': 'Tokelau', 'Alpha-2 code': 'TK', 'Alpha-3 code': 'TKL', 'Numeric': 772}, {'Country': 'Tonga', 'Alpha-2 code': 'TO', 'Alpha-3 code': 'TON', 'Numeric': 776}, {'Country': 'Trinidad and Tobago', 'Alpha-2 code': 'TT', 'Alpha-3 code': 'TTO', 'Numeric': 780}, {'Country': 'Tunisia', 'Alpha-2 code': 'TN', 'Alpha-3 code': 'TUN', 'Numeric': 788}, {'Country': 'Turkey', 'Alpha-2 code': 'TR', 'Alpha-3 code': 'TUR', 'Numeric': 792}, {'Country': 'Turkmenistan', 'Alpha-2 code': 'TM', 'Alpha-3 code': 'TKM', 'Numeric': 795}, {'Country': 'Turks and Caicos Islands (the)', 'Alpha-2 code': 'TC', 'Alpha-3 code': 'TCA', 'Numeric': 796}, {'Country': 'Tuvalu', 'Alpha-2 code': 'TV', 'Alpha-3 code': 'TUV', 'Numeric': 798}, {'Country': 'Uganda', 'Alpha-2 code': 'UG', 'Alpha-3 code': 'UGA', 'Numeric': 800}, {'Country': 'Ukraine', 'Alpha-2 code': 'UA', 'Alpha-3 code': 'UKR', 'Numeric': 804}, {'Country': 'United Arab Emirates (the)', 'Alpha-2 code': 'AE', 'Alpha-3 code': 'ARE', 'Numeric': 784}, {'Country': 'United Kingdom of Great Britain and Northern Ireland (the)', 'Alpha-2 code': 'GB', 'Alpha-3 code': 'GBR', 'Numeric': 826}, {'Country': 'United States Minor Outlying Islands (the)', 'Alpha-2 code': 'UM', 'Alpha-3 code': 'UMI', 'Numeric': 581}, {'Country': 'United States of America (the)', 'Alpha-2 code': 'US', 'Alpha-3 code': 'USA', 'Numeric': 840}, {'Country': 'Uruguay', 'Alpha-2 code': 'UY', 'Alpha-3 code': 'URY', 'Numeric': 858}, {'Country': 'Uzbekistan', 'Alpha-2 code': 'UZ', 'Alpha-3 code': 'UZB', 'Numeric': 860}, {'Country': 'Vanuatu', 'Alpha-2 code': 'VU', 'Alpha-3 code': 'VUT', 'Numeric': 548}, {'Country': 'Venezuela (Bolivarian Republic of)', 'Alpha-2 code': 'VE', 'Alpha-3 code': 'VEN', 'Numeric': 862}, {'Country': 'Viet Nam', 'Alpha-2 code': 'VN', 'Alpha-3 code': 'VNM', 'Numeric': 704}, {'Country': 'Virgin Islands (British)', 'Alpha-2 code': 'VG', 'Alpha-3 code': 'VGB', 'Numeric': 92}, {'Country': 'Virgin Islands (U.S.)', 'Alpha-2 code': 'VI', 'Alpha-3 code': 'VIR', 'Numeric': 850}, {'Country': 'Wallis and Futuna', 'Alpha-2 code': 'WF', 'Alpha-3 code': 'WLF', 'Numeric': 876}, {'Country': 'Western Sahara', 'Alpha-2 code': 'EH', 'Alpha-3 code': 'ESH', 'Numeric': 732}, {'Country': 'Yemen', 'Alpha-2 code': 'YE', 'Alpha-3 code': 'YEM', 'Numeric': 887}, {'Country': 'Zambia', 'Alpha-2 code': 'ZM', 'Alpha-3 code': 'ZMB', 'Numeric': 894}, {'Country': 'Zimbabwe', 'Alpha-2 code': 'ZW', 'Alpha-3 code': 'ZWE', 'Numeric': 716}]

class color:
   """Used to to color code text ouptut in order to highlight key pieces of information.
      
      Usage Example:  print(color.PURPLE + 'Hello World' + color.END) 
      
   """
   PURPLE = '\033[95m'
   CYAN = '\033[96m'
   DARKCYAN = '\033[36m'
   BLUE = '\033[94m'
   GREEN = '\033[92m'
   YELLOW = '\033[93m'
   RED = '\033[31m'
   ORANGE = '\033[33m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'

def analyst():
    """ The main function of the program.  Runs and infinite loop and checks the contents of the clipboard every 5 seconds to see if it has changed.  If so it then runs a series of checks to determine if it is one of the following:
    
    Hash (md5, sha1 or sha256)
    Port # or Windows EventID (requires user interaction to choose between the 2 or neither)
    Domain (lots of false positives here.  will trigger on things like first.last
    Private IP address
    Public IP address
    None of the above    
    """
    abuse_ip_db_headers = create_abuse_ip_db_headers_from_config()
    otx = create_av_otx_headers_from_config()
    virus_total_headers = create_virus_total_headers_from_config()
    clipboard_contents = get_clipboard_contents()

    while True:

        try:
            check = get_clipboard_contents()
        except TypeError as e:
            print('\n\n\n' + str(e))
            pass
        else:   
            try:
                if check != clipboard_contents:
                    clipboard_contents = check     
                    if re.match(hash_validation_regex, clipboard_contents):
                        suspect_hash = clipboard_contents
                        print_virus_total_hash_results(suspect_hash, virus_total_headers)
                    elif re.match(port_wid_validation_regex, clipboard_contents):
                        is_port_or_weivd(clipboard_contents)
                    elif validators.domain(clipboard_contents) == True:
                        suspect_domain = clipboard_contents
                        print_vt_domain_report(suspect_domain, virus_total_headers)
                    elif ipaddress.IPv4Address(clipboard_contents).is_private:
                        print('\n\n\nThis is an RFC1918 IP Address' +'\n\n\n')
                        pass
                    elif ipaddress.IPv4Address(clipboard_contents):
                        suspect_ip = clipboard_contents
                        get_ip_analysis_results(suspect_ip, virus_total_headers, abuse_ip_db_headers, otx)
                    else: 
                        continue
            except:
                continue
               
        
        time.sleep(5)

def check_abuse_ip_db(suspect_ip, abuse_ip_db_headers):
    """ Used to Automatically pull down and present relevant information from AbuseIPDB (https://www.abuseipdb.com/) of an IP address and print the information to the screen.  Requires an AbuseIP DB API-Key which is free but subject to daily limits.  Uses their APIv2.

    This funciton takes the followiong two parameters:
    
        IP address:  Obtained automatically from the main script in the Juptyer Notebook.
        
        AbuseIPDB Headers: Obtained automatically from the config.ini file and  the create_abuse_ip_db_headers_from_config function. 
    
    Sample Output:
        Abuse IP DB:
	        Abuse Confidence Score:   97%
	        Total Reports:            53
	        Last Reported:            2022-02-13T17:22:12+00:00
	        Distinct Reporters:       14
	        Usage Type:               Fixed Line ISP
	        Domain:                   inter.com.ru
	        https://www.abuseipdb.com/check/45.145.66.165
    """
    # Set variable for the current API Url
    abuse_ip_db_url = 'https://api.abuseipdb.com/api/v2/check'
    # Set variable for the max age in days to look back.  Their site asks no further back than 90 days in most cases.
    days = '90'
    # Format a clickable link to print along with the results in order to see additional information not printed to the screen or to verify the information is accurate.  Trust but verify.
    abuse_ip_link_url = 'https://www.abuseipdb.com/check/SUSPECT_IP_ADDRESS'
    # Takes the link above and replaces SUSPECT_IP_ADDRESS with the IP Address from the clipboard to format a clickable link and to print along with the results in order to see additional information not printed to the screen or to verify the information is accurate.  Trust but verify.
    abuse_ip_link_url = abuse_ip_link_url.replace("SUSPECT_IP_ADDRESS", suspect_ip)
    # Formats the query string to submit via the API.
    querystring = {
        'ipAddress': suspect_ip,
        'maxAgeInDays': days
    }
    
    response = requests.request(method='GET', url=abuse_ip_db_url, headers=abuse_ip_db_headers , params=querystring)

    abuse_ip_report = json.loads(response.text)
    
    print(color.UNDERLINE + '\nAbuse IP DB:' + color.END)
    if abuse_ip_report['data']['abuseConfidenceScore'] >= 70:
        print('\t{:<34} {}%'.format(color.RED + 'Abuse Confidence Score:' + color.END,abuse_ip_report['data']['abuseConfidenceScore'] )) 
    elif abuse_ip_report['data']['abuseConfidenceScore'] >= 40:
        print('\t{:<34} {}%'.format(color.ORANGE + 'Abuse Confidence Score:' + color.END,abuse_ip_report['data']['abuseConfidenceScore'] ))
    else:
        print('\t{:<25} {}%'.format('Abuse Confidence Score:',abuse_ip_report['data']['abuseConfidenceScore'] ))
    print('\t{:<25} {}'.format('Total Reports:',abuse_ip_report['data']['totalReports'] ))
    print('\t{:<25} {}'.format('Last Reported:',abuse_ip_report['data']['lastReportedAt'] ))
    print('\t{:<25} {}'.format('Distinct Reporters:',abuse_ip_report['data']['numDistinctUsers'] ))
    print('\t{:<25} {}'.format('Usage Type:',abuse_ip_report['data']['usageType'] ))
    print('\t{:<25} {}'.format('Domain:',abuse_ip_report['data']['domain'] ))
    print('\t' + abuse_ip_link_url)    
    
def check_tor(suspect_ip):
    """Queries the tor project to check if the submitted IP address is a known TOR Exit node.
    
    This funciton takes the followiong parameter:
    
        IP address:  Obtained automatically from the main script in the Juptyer Notebook.
        
    Sample output:
        TOR Exit Node:            No    
    """
    tor_url = "https://check.torproject.org/cgi-bin/TorBulkExitList.py"
    try:
        response = requests.request("GET", tor_url)
        count = 0
        if response.status_code == 200:
            tor_list = response.text.split('\n')
            for ip in tor_list:
                if suspect_ip == ip:
                    count = count + 1
                else:
                    count = count
        if count != 0:
            print("\n\t{:<25} {}".format('TOR Exit Node:', "Yes"))
        else:
            print("\n\t{:<25} {}".format('TOR Exit Node:', "No"))
    except Exception as e:
        print("\n\t{:<25} {}".format('TOR Exit Node:', "There was an error while checking for Tor exit nodes."))      

def create_abuse_ip_db_headers_from_config():
    """ Creates a dictionary called abuse_ip_db_headers that contains the formatted header needed to submit an query to AbuseIP DB.
    
    Requires an AbuseIP DB API Key to use.  It is free to sign up for one but has restrictions on daily limits.
    
    Reads in the AbuseIP DB API Key from the config.ini file.
    
    Note:  You are not required to use this module.  If you do not wish to use it then you can leave the config file as is with key = None
    
    Returns the Abuse IP DB API headers in the format of:
         abuse_ip_db_headers = {
            'Accept': abuse_headers['accept'],
            'Key': abuse_headers['key']
    """
    config_object = ConfigParser()
    try:
        config_object.read("config.ini")
    except:
        print("Error with config.ini.")
    else:
        abuse_headers = config_object["ABUSE_IP_DB"]

        if abuse_headers['key']:
            abuse_ip_db_headers = {
            'Accept': abuse_headers['accept'],
            'Key': abuse_headers['key']
        }
            print("Abuse IP DB Configured.")
            return abuse_ip_db_headers
        else:
            print("Abuse IP DB not configured.")
            print("Please add your Abuse IP DB API Key to the config.ini file if you want to use this module.")
            abuse_ip_db_headers = ''       
        
def create_av_otx_headers_from_config():
    """ Creates a dictionary called av_otx_headers that contains the formatted header needed to submit an query to AlienVault Open Threat Exchange (OTX).
    
    Requires an AlientVault OTX API Key to use.  It is free to sign up for one but has restrictions on daily limits.
    
    Reads in the AlientVault OTX API Key from the config.ini file.
    
    Note:  You are not required to use this module.  If you do not wish to use it then you can leave the config file as is with otx_api_key = None
    
    Returns the AlienVault OTX API Headers in the form of:
        av_otx_headers = OTXv2(av_headers['otx_api_key'], server=av_headers['server'])
    """

    config_object = ConfigParser()
    try:
        config_object.read("config.ini")
    except:
        print("Error with config.ini.")
    else:
        av_headers = config_object["ALIEN_VAULT_OTX"]

        if av_headers['otx_api_key']:
            av_otx_headers = OTXv2(av_headers['otx_api_key'], server=av_headers['server'])
            print("AlienVault OTX Configured.")
            return av_otx_headers
        else:
            print("AlienVault OTX not configured.")
            print("Please add your AlienVault OTX API Key to the config.ini file if you want to use this module.")
            av_otx_headers = ''  
        
def create_virus_total_headers_from_config():
    """ Creates a dictionary called virus_total_headers that contains the formatted header needed to submit an query to VirusTotal.
    
    Requires an VirusTotal API Key to use.  It is free to sign up for one but has restrictions on daily limits.
    
    Reads in the VirusTotal API Key from the config.ini file.
    
    Note:  You are not required to use this module but it is highly recommended as most of this tools current functionality is derived from VirusTotal.  If you do not wish to use it then you can leave the config file as is with x-apikey = None
    
    Returns VT API Headers in the form of:
        virus_total_headers = {
            'Accept': virus_total['accept'],
            'x-apikey': virus_total['x-apikey']
    
    """
    config_object = ConfigParser()
    try:
        config_object.read("config.ini")
    except:
        print("Error with config.ini.")
    else:
        virus_total = config_object["VIRUS_TOTAL"]

        if virus_total['x-apikey']:
            virus_total_headers = {
            'Accept': virus_total['accept'],
            'x-apikey': virus_total['x-apikey']
        }
            print("VirusTotal configured.")
            return virus_total_headers
        else:
            print("VirusTotal not configured.")
            print("Please add your VirusTotal API Key to the config.ini file if you want to use this module.")
            virus_total_headers = ''       
        
def get_clipboard_contents():
    """Gets the contents from the Windows clipboard and returns it so that it can be uesed in other functions.
    
    Example usage:  suspect_ip = get_clipboard_contents()
    
    """
    win32clipboard.OpenClipboard()
    clipboard_contents = win32clipboard.GetClipboardData().strip()
    win32clipboard.CloseClipboard()
    return clipboard_contents        
        
def get_ip_analysis_results(suspect_ip, virus_total_headers, abuse_ip_db_headers, otx):
    """ A function to call the various IP modules if they are enabled and display them in order.  
    
    This function requires the following 4 parameters:
        IP address:  Obtained automatically from the main script in the Juptyer Notebook.
        
        AbuseIPDB Headers: Obtained automatically from the config.ini file and  the create_abuse_ip_db_headers_from_config function.
        
        AlienVault OTX Headers: Obtained automatically from the config.ini file and  the create_av_otx_headers_from_config function.
        
        VirusTotal Headers: Obtained automatically from the config.ini file and  the create_virus_total_headers_from_config function.
    
    Note:  The 3 header parameters are all required even if you have not configured and API Key.  The function will validate if they are configured and pass over the ones that are not.        
    
    """
    heading = "\n\n\nIP Analysis Report for " + suspect_ip + ":"
    print(color.BOLD + heading + color.END)
    
    if virus_total_headers == None:
        print(color.UNDERLINE + '\nVirusToal Detections:' + color.END)
        print('\tVirus Total not configured.')
    else:
        get_vt_ip_results(suspect_ip, virus_total_headers)
        
    print(color.UNDERLINE + '\nIP Information:' + color.END)
    
    try:
        ip_whois(suspect_ip)
    except:
        pass
    
    check_tor(suspect_ip) 
    
    if abuse_ip_db_headers == None:
        print(color.UNDERLINE + '\nAbuse IP DB:' + color.END)
        print('\tAbuse IP DB not configured.')
    else:
        check_abuse_ip_db(suspect_ip, abuse_ip_db_headers) 
        
    if otx == None:
        print(color.UNDERLINE + '\nAlienVault OTX:' + color.END)
        print('\tAlienVault not configured.')
    else:  
        print_alient_vault_ip_results(otx, suspect_ip)
        
def get_vt_ip_results(suspect_ip, virus_total_headers):
    """A fuction to form the api query for an IP address to VirusTotal and pull back the results.  It then calls a 2nd function to process those results.

    This function requires the following 2 parameters:
        IP address:  Obtained automatically from the main script in the Juptyer Notebook.
        
        VirusTotal Headers: Obtained automatically from the config.ini file and  the create_virus_total_headers_from_config function.
    
    Sample Output:
        VirusToal Detections:
	       Malicious:                3
	       Malware:                  3
	       Suspicious:               0
	       Phishing:                 0
	       Spam:                     0
	       Clean:                    72
	       Undetected:               11
	       Time Out:                 0
	       https://www.virustotal.com/gui/ip-address/45.145.66.165
    """
    vt_ip_report = 'https://www.virustotal.com/api/v3/ip_addresses/SUSPECT_IP_ADDRESS'
    vt_ip_report = vt_ip_report.replace("SUSPECT_IP_ADDRESS", suspect_ip)
    response = requests.request("GET", vt_ip_report, headers=virus_total_headers)
    vt_ip_response = response.text 
    vt_ip_response = json.loads(vt_ip_response)
    
    print(color.UNDERLINE + '\nVirusToal Detections:' + color.END) 
    print_ip_detections(vt_ip_response)
    print("\thttps://www.virustotal.com/gui/ip-address/"+ suspect_ip)         
        
def ip_whois(suspect_ip):
    """  A function to query WhoIs for an IP address and print out information from the response.
    
    This function requires the following parameter:
        IP address:  Obtained automatically from the main script in the Juptyer Notebook.
    
    Sample Output:
        IP Information:
	        Organization:             RU-ITRESHENIYA
	        CIDR:                     45.145.66.0/23
	        Range:                    45.145.66.0 - 45.145.67.255
	        Country:                  Russian Federation (the)
	        Associated Email:
		            Email:            abuse@hostway.ru


	        Organization:             HOSTWAY route object
	        CIDR:                     45.145.66.0/23
	        Range:                    45.145.66.0 - 45.145.67.255
	        Country:                  None
	        Associated Email:
		            Email:            No associated emails.   
    """

    org_match = '([a-zA-Z0-9 .,_")(-]+)\n?'
    obj = IPWhois(suspect_ip)
    res = obj.lookup_whois()
    company_count = 0

    for line in res['nets']:
        if line['description'] != None:
            m = re.match(org_match, line['description'])
            org = m.group(1)
            company_count = company_count + 1
            print('\t{:<33} {}'.format(color.BOLD + 'Organization:' + color.END,org))
        elif  line['name'] != None:
            m = re.match(org_match, line['name'])
            org = m.group(1)
            company_count = company_count + 1
            print('\t{:<33} {}'.format(color.BOLD + 'Organization:' + color.END,org))
        else:
            print('\t{:<33} {}'.format(color.BOLD + 'Organization:' + color.END,'Org is blank in whois data.'))
        print('\t{:<25} {}'.format('CIDR:',line['cidr']))
        if line['range']:
            print('\t{:<25} {}'.format('Range:',line['range']))
        else:
            ip_range = ipaddress.ip_network(line['cidr'])
            ip_range = str(ip_range[0]) + ' - ' + str(ip_range[-1])
            print('\t{:<25} {}'.format('Range:',ip_range))
        country_code = line['country']
        print_country(country_code, countries)
        print('\tAssociated Email:')
        if line['emails'] == None:
            print('\t\t{:<17} {}'.format('Email:','No associated emails.'))
        else:
            for email in line['emails']:
                print('\t\t{:<17} {}'.format('Email:',email))
            print('\n')
    if company_count == 0:
        print('\t{:<25} {}'.format('ASN Description:',res['asn_description']))
    else:
        pass  

def is_ip_address(clipboard_contents):
    """A function to take the contents of the clipboard and determine if it is an IP address.  If it is an RFC 1918 address it prints 'This is an RFC1918 IP Address' to the screen.  If it is not an RFC 1918 address it returns the ip address.  
   
   Example usage:   suspect_ip = is_ip_address(clipboard_contents)
   
   This function requires the following paramater:
   
       clipboard_contents:  This is derived from the get_clipboard_contents() function.
   
   """
    try:
        if ipaddress.IPv4Address(clipboard_contents).is_private:
            print('This is an RFC1918 IP Address')
        elif ipaddress.IPv4Address(clipboard_contents):
            suspect_ip = clipboard_contents
            return suspect_ip
        else:
            pass
    except:
        pass    

def is_port_or_weivd(pwid):
    """ Takes contents of clipboard that matched the port_wid_validation_regex and prompts the use to input 1 for a port and 2 for a WID.  It then calls either the open_port_page or the open_wid_page function.
    
    Sample Output:
        Is this a Port or Windows Event ID?
        Press 1 for Port
        Press 2 for WEVID
        If neither then just press Enter
    """
    choice = input("\n\n\nIs this a Port or Windows Event ID?\nPress 1 for Port\nPress 2 for WEVID\nIf neither then just press Enter\n")
    if choice == '1':
        open_port_page(pwid)
    elif choice == '2':
        open_wid_page(pwid)
    else:
        pass    
    
def open_port_page(port):
    """
    Takes the contents of the clipboard that the user indicated was a port and prints out a clickable link to the Speedguide.net page for that port.
    
    Sample Output:
        https://www.speedguide.net/port.php?port=445
    """
    port_url = 'https://www.speedguide.net/port.php?port=PORT_ID'
    port_url = port_url.replace("PORT_ID", port)
    print("\n" + port_url)

def open_wid_page(wevid):
    """
    Takes the contents of the clipboard that the user indicated was a Windows Event ID (wevid) and prints out a clickable link to the ultimatewindowssecurity.com page for that wevid.
    
    Sample Ouput:
        https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4726
    """
    weivd_url = 'https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=W_EVID'
    wevid_url = weivd_url.replace("W_EVID", wevid)
    print("\n" + wevid_url)

def print_alient_vault_ip_results(otx, suspect_ip):
    """Takes the OTX Headers and suspect IP, pulls back inforamtion from OTX and prints it to the screen.
    
    This function requires the following 4 parameters:
        IP address:  Obtained automatically from the main script in the Juptyer Notebook.
             
        AlienVault OTX Headers: Obtained automatically from the config.ini file and  the create_av_otx_headers_from_config function.
    
    Sample Output:
        AlienVault OTX IP Report:
	    Related Pulses:           17
	    Reputation:               None
	    Passive DNS:              1 Domains
	    Hostname:                 bio4kobs.geekgalaxy.com
	        First Seen:             2019-07-02T13:13:35
	        Last Seen:              2019-07-11T13:45:12
	    https://otx.alienvault.com/indicator/ip/178.239.21.165
    """
    otx_results = otx.get_indicator_details_full(IndicatorTypes.IPv4,suspect_ip)
    
    print(color.UNDERLINE + "\nAlienVault OTX IP Report:"+ color.END)
    
    if otx_results['reputation']['reputation'] == None:
        print('\t{:<25} {}'.format('Reputation:','None'))
    else:
        print('\t{:<25} {}'.format('Pulse Modifed:',otx_results['reputation']['reputation']))  

    print('\t{:<25} {}'.format('Passive DNS:', str(otx_results['passive_dns']['count']) + ' Domains'))
    if otx_results['passive_dns']['count'] <= 5:
        for host in otx_results['passive_dns']['passive_dns']:
            print("\t{:<33} {}".format(color.BOLD + 'Hostname:' + color.END,host['hostname']))
            print("\t  {:<23} {}".format('First Seen:',host['first']))
            print("\t  {:<23} {}".format('Last Seen:',host['last']))
    print("\thttps://otx.alienvault.com/indicator/ip/" + suspect_ip)
    
def print_country(country_code, countries):
    """ Converts a 2 character country code to the full country name.
    
    This function requires the following 2 paramaters:
         Country Code:
         
         Countries: Currently statical defined as a list of dictionaires for each country.
         
         Country Code: Derived from the IPWHois resulst in the ip_whois function.
    Sample Output:
        Country:                  United States of America (the)
    """

    if country_code == None:
        country = country_code
    else:
        country_code = country_code.upper()
        country = country_code
    
    for line in countries:
        if country_code == line['Alpha-2 code']:
            country = line['Country']
        else:
            pass

    if country != '':
        print('\t{:<25} {}'.format('Country:',country))  
    else:
        print('\t{:<25} {}'.format('Country:','No Country in whois record'))   
    
def print_domain_detections(vt_domain_response):
    """ Takes the response from the virustotal api, counts the # of each categorey (malicious, suspicious, phishing, malware, spam, 'clean, unrated, time out)and then prints to screen with color coding.  Red = 10 or more detections in that category.  Oragne = 5 to 9 detections in that category.  
    
    This function requires the following parameter:
    
        vt_domain_response - Derived from the function        print_vt_domain_report
    
    Sample output:
        Last Analysis Stats:
	        Malicious:                4
            Malware:                  2
            Suspicious:               1
            Phishing:                 8
            Spam:                     0
            Clean:                    66
            Undetected:               8
            Time Out:                 0
    """
    categories = [value for value in vt_domain_response['data']['attributes']['last_analysis_results'].values()]
    alert_categories = {'malicious': 0, 'suspicious': 0, 'phishing': 0, 'malware': 0, 'spam': 0, 'clean': 0, 'unrated': 0, 'time out': 0}
    for alert in categories:
        if alert['result'] in alert_categories:
            alert_categories[alert['result']] = alert_categories[alert['result']] + 1
        else:
            continue
    
    if alert_categories['malicious'] >= 10:
        print('\t{:<31} {}'.format(color.RED + 'Malicious:' + color.END,alert_categories['malicious'])) 
    elif alert_categories['malicious'] >= 5:
        print('\t{:<34} {}'.format(color.ORANGE + 'Malicious:' + color.END,alert_categories['malicious']))
    else:
        print('\t{:<25} {}'.format('Malicious:',alert_categories['malicious']))
        
    if alert_categories['malware'] >= 10:
        print('\t{:<31} {}'.format(color.RED + 'Malware:' + color.END,alert_categories['malware'])) 
    elif alert_categories['malware'] >= 5:
        print('\t{:<34} {}'.format(color.ORANGE + 'Malware:' + color.END,alert_categories['malware']))
    else:
        print('\t{:<25} {}'.format('Malware:',alert_categories['malware']))
    
    if alert_categories['suspicious'] >= 10:
        print('\t{:<31} {}'.format(color.RED + 'Suspicious:' + color.END,alert_categories['suspicious'])) 
    elif alert_categories['suspicious'] >= 5:
        print('\t{:<34} {}'.format(color.ORANGE + 'Suspicious:' + color.END,alert_categories['suspicious']))
    else:
        print('\t{:<25} {}'.format('Suspicious:',alert_categories['suspicious']))
    
    if alert_categories['phishing'] >= 10:
        print('\t{:<31} {}'.format(color.RED + 'Phishing:' + color.END,alert_categories['phishing'])) 
    elif alert_categories['phishing'] >= 5:
        print('\t{:<34} {}'.format(color.ORANGE + 'Phishing:' + color.END,alert_categories['phishing']))
    else:
        print('\t{:<25} {}'.format('Phishing:',alert_categories['phishing']))
        
    if alert_categories['spam'] >= 10:
        print('\t{:<31} {}'.format(color.RED + 'Spam:' + color.END,alert_categories['spam'])) 
    elif alert_categories['spam'] >= 5:
        print('\t{:<34} {}'.format(color.ORANGE + 'Spam:' + color.END,alert_categories['spam']))
    else:
        print('\t{:<25} {}'.format('Spam:',alert_categories['spam']))
     
    print('\t{:<25} {}'.format('Clean:',alert_categories['clean']))
    print('\t{:<25} {}'.format('Undetected:',alert_categories['unrated']))
    print('\t{:<25} {}'.format('Time Out:',alert_categories['time out']))                  
   
    
def print_ip_detections(vt_ip_response):
    """ Takes the response from the virustotal api, counts the # of each category (malicious, suspicious, phishing, malware, spam, 'clean, unrated, time out)and then prints to screen with color coding.  Red = 10 or more detections in that category.  Oragne = 5 to 9 detections in the (malicious, suspicious, phishing, malware, spam) categories.  
    
    This function requires the following parameter:
    
        vt_ip_response - Derived from the function        get_vt_ip_results
    
    Sample Output:
    	Malicious:                3
        Malware:                  3
        Suspicious:               0
        Phishing:                 0
        Spam:                     0
        Clean:                    72
        Undetected:               11
        Time Out:                 0
    """
    categories = [value for value in vt_ip_response['data']['attributes']['last_analysis_results'].values()]
    alert_categories = {'malicious': 0, 'suspicious': 0, 'phishing': 0, 'malware': 0, 'spam': 0, 'clean': 0, 'unrated': 0, 'time out': 0}
    for alert in categories:
        if alert['result'] in alert_categories:
            alert_categories[alert['result']] = alert_categories[alert['result']] + 1
        else:
            continue
    
    if alert_categories['malicious'] >= 10:
        print('\t{:<31} {}'.format(color.RED + 'Malicious:' + color.END,alert_categories['malicious'])) 
    elif alert_categories['malicious'] >= 5:
        print('\t{:<34} {}'.format(color.ORANGE + 'Malicious:' + color.END,alert_categories['malicious']))
    else:
        print('\t{:<25} {}'.format('Malicious:',alert_categories['malicious']))
        
    if alert_categories['malware'] >= 10:
        print('\t{:<31} {}'.format(color.RED + 'Malware:' + color.END,alert_categories['malware'])) 
    elif alert_categories['malware'] >= 5:
        print('\t{:<34} {}'.format(color.ORANGE + 'Malware:' + color.END,alert_categories['malware']))
    else:
        print('\t{:<25} {}'.format('Malware:',alert_categories['malware']))
    
    if alert_categories['suspicious'] >= 10:
        print('\t{:<25} {}'.format(color.RED + 'Suspicious:' + color.END,alert_categories['suspicious'])) 
    elif alert_categories['suspicious'] >= 5:
        print('\t{:<25} {}'.format(color.ORANGE + 'Suspicious:' + color.END,alert_categories['suspicious']))
    else:
        print('\t{:<25} {}'.format('Suspicious:',alert_categories['suspicious']))
    
    if alert_categories['phishing'] >= 10:
        print('\t{:<25} {}'.format(color.RED + 'Phishing:' + color.END,alert_categories['phishing'])) 
    elif alert_categories['phishing'] >= 5:
        print('\t{:<25} {}'.format(color.ORANGE + 'Phishing:' + color.END,alert_categories['phishing']))
    else:
        print('\t{:<25} {}'.format('Phishing:',alert_categories['phishing']))
        
    if alert_categories['spam'] >= 10:
        print('\t{:<31} {}'.format(color.RED + 'Spam:' + color.END,alert_categories['spam'])) 
    elif alert_categories['spam'] >= 5:
        print('\t{:<34} {}'.format(color.ORANGE + 'Spam:' + color.END,alert_categories['spam']))
    else:
        print('\t{:<25} {}'.format('Spam:',alert_categories['spam']))
     
    print('\t{:<25} {}'.format('Clean:',alert_categories['clean']))
    print('\t{:<25} {}'.format('Undetected:',alert_categories['unrated']))
    print('\t{:<25} {}'.format('Time Out:',alert_categories['time out']))
    
def print_virus_total_hash_results(suspect_hash, virus_total_headers):
    """Queries VirusTotal via the API for a suspect hash and prints the results to the screen.  For each hash it will color code output for the malicious and suspicious categories. Red = 10 or more detections in that category.  Oragne = 5 to 9 detections in the (malicious, suspicious, phishing, malware, spam) categories.  
    
    This function requires the following 2 parameters:
    
        Suspect Hash:  derived from matching clipboard contents against the hash_validation_regex
    
        Virus Total Headers:  derive from the create_virus_total_headers_from_config function.    
    
    Sample Output:
        VirusTotal Hash Report for 82c8db5f3a0fab2062df72c228ef5889:
            File Reputation:
                Malicious:                36
                Suspicious:               0
                Harmless:                 0
                Undetected:               26

            File Threat Classification:
	            trojan                    19

            File Threat Name:
	            linux                     25
	            mirai                     22
	            smlem                     2

            File Info:
                Signature:                File not signed
                Signers:                  N/A
                Signing Date:             N/A
                File Type:                ELF
                Product:                  N/A
                Copyright:                N/A
                Decription:               N/A
                Creation Date:            N/A
                Last Modification Date:   2022-02-13 14:38:27

            Submission Info:
                Last Submission:          2022-02-13 14:33:19
                Last Analysis:            2022-02-13 14:33:19
                First Submission:         2022-02-13 14:33:19
                Times Submitted:          1
             https://www.virustotal.com/gui/file/82c8db5f3a0fab2062df72c228ef5889/detection
    """
    vt_hash_url = 'https://www.virustotal.com/gui/file/SUSPECT_HASH/detection'
    vt_hash_report = "https://www.virustotal.com/api/v3/files/SUSPECT_HASH"
    vt_hash_report = vt_hash_report.replace("SUSPECT_HASH", suspect_hash)
    vt_hash_url = vt_hash_url.replace("SUSPECT_HASH", suspect_hash)
    heading = "\n\n\nVirusTotal Hash Report for " + suspect_hash + ":"
    print(color.BOLD + heading + color.END)
    response = requests.request("GET", vt_hash_report, headers=virus_total_headers)

    vt_hash_response = json.loads(response.text)

    try:
        vt_hash_response['data']
    except:
        print(color.UNDERLINE + 'File Reputation:' + color.END)
        print('\tFile hash not found in VirusTotal')
    else:
        print(color.UNDERLINE + 'File Reputation:' + color.END)
        
        if vt_hash_response['data']['attributes']['last_analysis_stats']['malicious'] >= 10:
            print('\t{:<34} {}'.format(color.RED + 'Malicious:' + color.END,vt_hash_response['data']['attributes']['last_analysis_stats']['malicious'])) 
        elif vt_hash_response['data']['attributes']['last_analysis_stats']['malicious'] >= 5:
            print('\t{:<25} {}'.format(color.ORANGE + 'Malicious:' + color.END,vt_hash_response['data']['attributes']['last_analysis_stats']['malicious']))
        else:
            print('\t{:<25} {}'.format('Malicious:',vt_hash_response['data']['attributes']['last_analysis_stats']['malicious']))
        
        
        if vt_hash_response['data']['attributes']['last_analysis_stats']['suspicious'] >= 10:
            print('\t{:<25} {}'.format(color.RED + 'Suspicious:' + color.END,vt_hash_response['data']['attributes']['last_analysis_stats']['suspicious'])) 
        elif vt_hash_response['data']['attributes']['last_analysis_stats']['suspicious'] >= 5:
            print('\t{:<25} {}'.format(color.ORANGE + 'Suspicious:' + color.END,vt_hash_response['data']['attributes']['last_analysis_stats']['suspicious']))
        else:
            print('\t{:<25} {}'.format('Suspicious:',vt_hash_response['data']['attributes']['last_analysis_stats']['suspicious']))
        
        print('\t{:<25} {}'.format('Harmless:',vt_hash_response['data']['attributes']['last_analysis_stats']['harmless']))       
        print('\t{:<25} {}'.format('Undetected:',vt_hash_response['data']['attributes']['last_analysis_stats']['undetected']))


        print(color.UNDERLINE + '\nFile Threat Classification:' + color.END)
        try:
            vt_hash_response['data']['attributes']['popular_threat_classification']['popular_threat_category']
        except KeyError:
            print('\tThis hash does not have a Threat Classification')
        else:
            for line in vt_hash_response['data']['attributes']['popular_threat_classification']['popular_threat_category']:
                print('\t{:<25} {}'.format(line['value'],line['count']))
        
        print(color.UNDERLINE + '\nFile Threat Name:' + color.END)
        try:
            vt_hash_response['data']['attributes']['popular_threat_classification']['popular_threat_name']
        except KeyError:
            print('\tThis hash does not have an associated Threat Name.')
        else:
            for line in vt_hash_response['data']['attributes']['popular_threat_classification']['popular_threat_name']:
                print('\t{:<25} {}'.format(line['value'],line['count']))
    
        print(color.UNDERLINE + '\nFile Info:' + color.END)
        try:
            vt_hash_response['data']['attributes']['signature_info']['verified']
        except KeyError:
            print('\t{:<25} {}'.format('Signature:','File not signed'))
        else:
            print('\t{:<25} {}'.format('Signature:',vt_hash_response['data']['attributes']['signature_info']['verified']))
        
        try:
            vt_hash_response['data']['attributes']['signature_info']['signers details']
        except KeyError:
            print('\t{:<25} {}'.format('Signers:','N/A'))
        else:
            print('\n\tSigner(s):')
            for line in vt_hash_response['data']['attributes']['signature_info']['signers details']:
                if line['status'] == 'Valid':
                    print('\t\t{:<50} {:<25}'.format(line['name'],line['status']))
                else:
                    print('\t\t{:<50} {:<25}'.format(line['name'],'Not Valid'))
        
        try:
            vt_hash_response['data']['attributes']['signature_info']['signing date']
        except KeyError as e:
            print('\t{:<25} {}'.format('Signing Date:','N/A'))
        else:
             print('\n\t{:<25} {}'.format('Signing Date:',vt_hash_response['data']['attributes']['signature_info']['signing date']))
    
        try:
            vt_hash_response['data']['attributes']['type_description']
        except KeyError as e:
            print('\t{:<25} {}'.format('File Type:','N/A'))
        else:
            print('\t{:<25} {}'.format('File Type:',vt_hash_response['data']['attributes']['type_description']))
        
        try:
            vt_hash_response['data']['attributes']['signature_info']['product']
        except KeyError as e:
            print('\t{:<25} {}'.format('Product:','N/A'))
        else:
            print('\t{:<25} {}'.format('Product:',vt_hash_response['data']['attributes']['signature_info']['product']))
            
        try:
            vt_hash_response['data']['attributes']['signature_info']['copyright']
        except KeyError as e:
            print('\t{:<25} {}'.format('Copyright:','N/A'))
        else:
            print('\t{:<25} {}'.format('Copyright:',vt_hash_response['data']['attributes']['signature_info']['copyright']))
        
        try:
            vt_hash_response['data']['attributes']['signature_info']['description']
        except KeyError as e:
            print('\t{:<25} {}'.format('Decription:','N/A'))
        else:
            print('\t{:<25} {}'.format('Decription:',vt_hash_response['data']['attributes']['signature_info']['description']))
        
        try:
            vt_hash_response['data']['attributes']['creation_date']
        except KeyError as e:
            print('\t{:<25} {}'.format('Creation Date:','N/A'))
        else:
            print('\t{:<25} {}'.format('Creation Date:',datetime.datetime.fromtimestamp(vt_hash_response['data']['attributes']['creation_date'])))
        
        try:
            vt_hash_response['data']['attributes']['last_modification_date']
        except KeyError as e:
            print('\t{:<25} {}'.format('Last Modification Date:','N/A'))
        else:
             print('\t{:<25} {}'.format('Last Modification Date:',datetime.datetime.fromtimestamp(vt_hash_response['data']['attributes']['last_modification_date'])))

        print(color.UNDERLINE + '\nSubmission Info:' + color.END)
        
        try:
            vt_hash_response['data']['attributes']['last_submission_date']
        except KeyError as e:
            print('\t{:<25} {}'.format('Last Submission:','N/A'))
        else:
            print('\t{:<25} {}'.format('Last Submission:',datetime.datetime.fromtimestamp(vt_hash_response['data']['attributes']['last_submission_date'])))
        
        try:
            vt_hash_response['data']['attributes']['last_analysis_date']
        except KeyError as e:
            print('\t{:<25} {}'.format('Last Analysis:','N/A'))
        else:
            print('\t{:<25} {}'.format('Last Analysis:',datetime.datetime.fromtimestamp(vt_hash_response['data']['attributes']['last_analysis_date'])))
        
        try:
            vt_hash_response['data']['attributes']['first_submission_date']
        except KeyError as e:
            print('\t{:<25} {}'.format('First Submission:','N/A'))
        else:
            print('\t{:<25} {}'.format('First Submission:',datetime.datetime.fromtimestamp(vt_hash_response['data']['attributes']['first_submission_date'])))
        
        try:
            vt_hash_response['data']['attributes']['times_submitted']
        except KeyError as e:
            print('\t{:<25} {}'.format('Times Submitted:','N/A'))
        else:
            print('\t{:<25} {}'.format('Times Submitted:',vt_hash_response['data']['attributes']['times_submitted']))
        print(vt_hash_url)
        
def print_vt_domain_report(suspect_domain, virus_total_headers):
    """ Queries VirusTotal via the API and prints the specified information to the screen.
    
    This funciton requires the following 2 parameters:
    
        Supect Domain - Derived from checking the clipboard contents agaisnt validators.domain.

        VirusTotal Headers - dereived from the create_virus_total_headers_from_config function
        
    Sample Output:
        Domain Reputation for kamery112.xyz:
        Last Analysis Stats:
            Malicious:                4
            Malware:                  2
            Suspicious:               1
            Phishing:                 8
            Spam:                     0
            Clean:                    66
            Undetected:               8
            Time Out:                 0

        Domain Info:
            Creation Date:                 2021-12-04 19:00:00
            Last Update Date:              2021-12-04 19:00:00
            Last Modification Date:        2022-02-08 21:35:04

        Certificate Info:
            Issuer:                        GoGetSSL
            Not After:                     2022-11-20 23:59:59
            Not Before:                    2021-10-20 00:00:00
        https://www.virustotal.com/gui/domain/kamery112.xyz
    """

    creation_date_regex = '(created|Creation Date): ([0-9T:-]+)Z?\\n'
    vt_domain_report = "https://www.virustotal.com/api/v3/domains/SUSPECT_DOMAIN"
    vt_domain_report = vt_domain_report.replace("SUSPECT_DOMAIN", suspect_domain)
    response = requests.request("GET", vt_domain_report, headers=virus_total_headers)
    vt_domain_response = response.text
    vt_domain_response = json.loads(vt_domain_response)

    try:
        vt_domain_response['data']
    except:
        print('\n\n\n' + color.BOLD + 'Domain Reputation for ' + suspect_domain + ':' + color.END)
        print('\tDomain not found in VirusTotal')  
    else:    
        print('\n\n\n' + color.BOLD + 'Domain Reputation for ' + suspect_domain + ':' + color.END)
   
    print(color.UNDERLINE + 'Last Analysis Stats:' + color.END)
    print_domain_detections(vt_domain_response)
    print(color.UNDERLINE + '\nDomain Info:' + color.END)
        
    try:
        vt_domain_response['data']['attributes']['creation_date']
    except:
        if re.search(creation_date_regex, vt_domain_response['data']['attributes']['whois']) != None:
            m =  m = re.search(creation_date_regex, vt_domain_response['data']['attributes']['whois'])
            cd = m.group(2)
            print('\t{:<30} {}'.format('Creation Date:',cd))
        else:
            print('\t{:<30} {}'.format('Creation Date:','No Date in VT'))
    else:
        datetime.datetime.fromtimestamp(vt_domain_response['data']['attributes']['creation_date'])
        print('\t{:<30} {}'.format('Creation Date:',datetime.datetime.fromtimestamp(vt_domain_response['data']['attributes']['creation_date'])))
        
    try:
        vt_domain_response['data']['attributes']['last_update_date']
    except:
        print('\t{:<30} {}'.format('Last Update Date:','No Data'))
    else:
        print('\t{:<30} {}'.format('Last Update Date:',datetime.datetime.fromtimestamp(vt_domain_response['data']['attributes']['last_update_date'])))

    try:
        vt_domain_response['data']['attributes']['last_modification_date']
    except:
        print('\t{:<30} {}'.format('Last Modification Date:','No Data'))
    else:
        print('\t{:<30} {}'.format('Last Modification Date:',datetime.datetime.fromtimestamp(vt_domain_response['data']['attributes']['last_modification_date'])))        


    print(color.UNDERLINE + '\nCertificate Info:' + color.END)
    try:
        vt_domain_response['data']['attributes']['last_https_certificate']['issuer']['O']
    except:
        print('\t{:<30} {}'.format('Issuer:','No Data'))
    else:
        print('\t{:<30} {}'.format('Issuer:',vt_domain_response['data']['attributes']['last_https_certificate']['issuer']['O']))
   

    try:
        vt_domain_response['data']['attributes']['last_https_certificate']['validity']['not_after']
    except:
        print('\t{:<30} {}'.format('Not After:','No Data'))
    else:
        print('\t{:<30} {}'.format('Not After:',vt_domain_response['data']['attributes']['last_https_certificate']['validity']['not_after']))

    try:
        vt_domain_response['data']['attributes']['last_https_certificate']['validity']['not_before']
    except:
        print('\t{:<30} {}'.format('Not Before:','No Data'))
    else:
        print('\t{:<30} {}'.format('Not Before:',vt_domain_response['data']['attributes']['last_https_certificate']['validity']['not_before']))
    print("https://www.virustotal.com/gui/domain/"+ suspect_domain)
