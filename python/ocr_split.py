import os
import ocrmypdf
from PyPDF2 import PdfFileWriter, PdfFileReader

print('please ensure you have Tesseract, ocrmypdf and PyPDF2 installed before running this script')
print('pip install ocrmypdf')
print('pip install PyPDF2')
print('apt install tesseract-ocr -y')

source_path = input('Path to source : ')
l = len(source_path)
file_name = source_path[:l - 4]

if __name__ == '__main__':  # To ensure correct behavior on Windows and macOS
    ocrmypdf.ocr(source_path, source_path, deskew=True, oversample=300)

inputpdf = PdfFileReader(open(source_path, "rb"))

for i in range(inputpdf.numPages):
    output = PdfFileWriter()
    output.addPage(inputpdf.getPage(i))
    with open(f"{file_name}-page%s.pdf" % i, "wb") as outputStream:
        output.write(outputStream)