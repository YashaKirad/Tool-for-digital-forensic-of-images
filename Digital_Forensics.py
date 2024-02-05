import numpy as np
import numpy.matlib as npm
import argparse
import json
import pprint
import exifread
import cv2 as cv
import os
import pywt
import math
import progressbar
import warnings
from scipy import ndimage
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from matplotlib import pyplot as plt
from os.path import basename


def main():
    argparser = argparse.ArgumentParser(description="Digital Image Forensics")
    # argparser.add_argument("-e", help='export EXIF to XML')
    argparser.add_argument("datafile", metavar='file', help='name of the image file')

    argparser.add_argument("-e", "--exif", help="exposing digital forgeries by EXIF metadata", action="store_true")
    argparser.add_argument("-gm", "--jpegghostm", help="exposing digital forgeries by JPEG Ghost (Multiple)", action="store_true")
    argparser.add_argument("-g", "--jpegghost", help="exposing digital forgeries by JPEG Ghost", action="store_true")
    argparser.add_argument("-n1", "--noise1", help="exposing digital forgeries by using noise inconsistencies", action="store_true")
    argparser.add_argument("-n2", "--noise2", help="exposing digital forgeries by using Median-filter noise residue inconsistencies", action="store_true")
    argparser.add_argument("-el", "--ela", help="exposing digital forgeries by using Error Level Analysis", action="store_true")
    argparser.add_argument("-cf", "--cfa", help="Image tamper detection based on demosaicing artifacts", action="store_true")
    argparser.add_argument("-q", "--quality", help="resaved image quality", type=int)
    argparser.add_argument("-s", "--blocksize", help="block size kernel mask", type=int)

    # Parses arguments
    args = argparser.parse_args()

    if not check_file(args.datafile):
        print("Invalid file. Please make sure the file exists and is of type JPEG")
        return

    if args.exif:
        exif_check(args.datafile)
    elif args.jpegghostm:
        jpeg_ghost_multiple(args.datafile)
    elif args.jpegghost:
        jpeg_ghost(args.datafile, args.quality)
    elif args.noise1:
        noise_inconsistencies(args.datafile, args.blocksize)
    elif args.noise2:
        median_noise_inconsistencies(args.datafile, args.blocksize)
    elif args.ela:
        ela(args.datafile, args.quality, args.blocksize)
    elif args.cfa:
        cfa_tamper_detection(args.datafile)
    else:
        exif_check(args.datafile)


def check_file(data_path):
    if not os.path.isfile(data_path):
        return False
    if not data_path.lower().endswith(('.jpg', '.jpeg')):
        return False
    return True


def exif_check(file_path):
    # Open image file for reading (binary mode)
    f = open(file_path, 'rb')

    # Return Exif tags
    tags = exifread.process_file(f)

    # Get the pure EXIF data of Image
    exif_code_form = extract_pure_exif(file_path)
    if exif_code_form is None:
        print("The EXIF data has been stripped. Photo may be taken from Facebook, Twitter, imgur")
        return

    # Check Modify Date
    check_software_modify(exif_code_form)
    check_modify_date(exif_code_form)
    check_original_date(exif_code_form)
    check_camera_information(tags)
    check_gps_location(exif_code_form)
    check_author_copyright(exif_code_form)

    # Print Raw Image Metadata
    print("\nRAW IMAGE METADATA")
    print("============================================================= \n")
    print("EXIF Data")
    for tag in tags.keys():
        if tag not in ('JPEGThumbnail', 'TIFFThumbnail', 'Filename', 'EXIF MakerNote'):
            print("%-35s: %s" % (tag, tags[tag]))


def extract_pure_exif(file_name):
    img = Image.open(file_name)
    info = img._getexif()
    return info


def decode_exif_data(info):
    exif_data = {}
    if info:
        for tag, value in info.items():
            decoded = TAGS.get(tag, tag)
            exif_data[decoded] = value
    return exif_data


def get_if_exist(data, key):
    if key in data:
        return data[key]
    return None


def export_json(data):
    with open('data.txt', 'w') as outfile:
        pass


# Check Software Edit
def check_software_modify(info):
    software = get_if_exist(info, 0x0131)
    if software is not None:
        print("Image edited with: %s" % software)
        return True
    return False


def check_modify_date(info):
    modify_date = get_if_exist(info, 0x0132)
    if modify_date is not None:
        print("Photo has been modified since it was created. Modified: %s" % modify_date)
        return True
    return False


def check_original_date(info):
    original_date = get_if_exist(info, 0x9003)
    create_date = get_if_exist(info, 0x9004)
    if original_date is not None:
        print("The shutter actuation time: %s" % original_date)
    if create_date is not None:
        print("Image created at: %s" % create_date)


def check_camera_information_2(info):
    make = get_if_exist(info, 0x010f)
    model = get_if_exist(info, 0x0110)
    exposure = get_if_exist(info, 0x829a)
    aperture = get_if_exist(info, 0x829d)
    focal_length = get_if_exist(info, 0x920a)
    iso_speed = get_if_exist(info, 0x8827)
    flash = get_if_exist(info, 0x9209)

    print("\nCamera Information")
    print("Make: \t \t %s" % make)
    print("Model: \t \t %s" % model)
    # 
    print("Exposure: \t \t %s " % exposure)
    print("Aperture: \t \t %s" % aperture)
    print("Focal Length: \t \t %s" % focal_length)
    #
    print("ISO Speed: \t %s" % iso_speed)
    print("Flash: \t \t %s" % flash)


def check_camera_information(info):
    make = get_if_exist(info, 'Image Make')
    model = get_if_exist(info, 'Image Model')
    exposure = get_if_exist(info, 'EXIF ExposureTime')
    aperture = get_if_exist(info, 'EXIF ApertureValue')
    focal_length = get_if_exist(info, 'EXIF FocalLength')
    iso_speed = get_if_exist(info, 'EXIF ISOSpeedRatings')
    flash = get_if_exist(info, 'EXIF Flash')

    print("\nCamera Information")
    print("Make: \t \t %s" % make)
    print("Model: \t \t %s" % model)
    # print("Exposure: \t \t %s " % exposure)
    # print("Aperture: \t \t %s" % aperture)
    # print("Focal Length: \t \t %s" % focal_length)
    print("ISO Speed: \t %s" % iso_speed)
    print("Flash: \t \t %s" % flash)


def check_gps_location(info):
    latitude = get_if_exist(info, 0x0002)
    longitude = get_if_exist(info, 0x0004)
    if latitude is not None:
        print("Latitude: %s" % latitude)
    if longitude is not None:
        print("Longitude: %s" % longitude)


def check_author_copyright(info):
    author = get_if_exist(info, 0x0080)
    copyright = get_if_exist(info, 0x8298)
    if author is not None:
        print("Author: %s" % author)
    if copyright is not None:
        print("Copyright: %s" % copyright)


if __name__ == '__main__':
    main()