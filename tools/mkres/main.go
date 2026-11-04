//go:build ignore

package main

import (
	"image"
	"image/color"
	_ "image/png"
	"log"
	"os"

	"github.com/tc-hib/winres"
	"github.com/tc-hib/winres/version"
)

func load(p string) image.Image {
	f, err := os.Open(p)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	img, _, err := image.Decode(f)
	if err != nil {
		log.Fatal(err)
	}
	return img
}

func clamp(v float64) uint8 {
	if v < 0 {
		return 0
	}
	if v > 255 {
		return 255
	}
	return uint8(v + 0.5)
}

func recolor(src image.Image, to color.NRGBA) image.Image {
	b := src.Bounds()
	dst := image.NewNRGBA(b)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			c := color.NRGBAModel.Convert(src.At(x, y)).(color.NRGBA)
			t := (float64(c.G) - float64(c.B) - 6) / 165
			if t < 0 {
				t = 0
			}
			if t > 1 {
				t = 1
			}
			dst.SetNRGBA(x, y, color.NRGBA{
				R: clamp(float64(c.R) + t*(float64(to.R)-207)),
				G: clamp(float64(c.G) + t*(float64(to.G)-245)),
				B: clamp(float64(c.B) + t*(float64(to.B)-74)),
				A: c.A,
			})
		}
	}
	return dst
}

func iconOf(imgs []image.Image) *winres.Icon {
	icon, err := winres.NewIconFromImages(imgs)
	if err != nil {
		log.Fatal(err)
	}
	return icon
}

func main() {
	dir := os.Args[1]
	out := os.Args[2]
	var imgs []image.Image
	for _, s := range []string{"256", "128", "64", "48", "40", "32", "24", "20", "16"} {
		imgs = append(imgs, load(dir+"/icon_"+s+".png"))
	}
	rs := winres.ResourceSet{}
	if err := rs.SetIcon(winres.ID(1), iconOf(imgs)); err != nil {
		log.Fatal(err)
	}
	for i, c := range []color.NRGBA{{112, 112, 108, 255}, {245, 178, 62, 255}} {
		var alt []image.Image
		for _, im := range imgs {
			alt = append(alt, recolor(im, c))
		}
		if err := rs.SetIcon(winres.ID(uint16(2+i)), iconOf(alt)); err != nil {
			log.Fatal(err)
		}
	}
	rs.SetManifest(winres.AppManifest{
		Identity:            winres.AssemblyIdentity{Name: "Volfram", Version: [4]uint16{1, 0, 8, 0}},
		Description:         "Volfram",
		Compatibility:       winres.Win10AndAbove,
		ExecutionLevel:      winres.AsInvoker,
		DPIAwareness:        winres.DPIPerMonitorV2,
		UseCommonControlsV6: true,
	})
	v := version.Info{}
	v.SetFileVersion("1.0.8.0")
	v.SetProductVersion("1.0.8.0")
	for k, val := range map[string]string{
		version.CompanyName:      "Volfram",
		version.FileDescription:  "Volfram",
		version.ProductName:      "Volfram",
		version.OriginalFilename: "Volfram.exe",
		version.InternalName:     "Volfram",
		version.LegalCopyright:   "Volfram",
		version.FileVersion:      "1.0.8",
		version.ProductVersion:   "1.0.8",
	} {
		v.Set(version.LangDefault, k, val)
	}
	rs.SetVersionInfo(v)
	f, err := os.Create(out)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	if err := rs.WriteObject(f, winres.ArchAMD64); err != nil {
		log.Fatal(err)
	}
	log.Println("written", out)
}
