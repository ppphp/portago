package atom

import (
	"bufio"
	"os"
)

type AbstractFormatter struct {
	Writer *bufio.Writer
	StyleStack []string
	HardBreak bool
}
func (a *AbstractFormatter) SendLineBreak(){
	a.Writer.Write([]byte("\n"))
}
func (a *AbstractFormatter) SendLiteralData(s string){
	a.Writer.Write([]byte(s))
}
func (a *AbstractFormatter) PushStyle(ss []string){
	a.StyleStack = append(a.StyleStack, ss...)
}
func (a *AbstractFormatter) PopStyle(s string){
	a.Writer.Write([]byte(s))
}


type StyleWriter struct {
	File *os.File
	StyleListener []string
}
func (d *StyleWriter) Flush(){
}
func (d *StyleWriter) SendLineBreak(){
	d.File.Write([]byte("\n"))
}
func (d *StyleWriter) SendLiteralData(s string){
	d.File.Write([]byte(s))
}
func (d *StyleWriter) NewStyles(s string){
	d.File.Write([]byte(s))
}
