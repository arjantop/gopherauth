package util

import (
	"html/template"
	"io"
	"path"
	"sync"
)

// TemplateFactory is a wrapper around html/template that contains all the
// tamples that can then be executed using a template name.
type TemplateFactory struct {
	// Filesystem path that templates are read from
	templateRoot string
	templates    map[string]*template.Template // Map of all the templates
	// Mutex for synchronizing access to templates map
	mutex *sync.Mutex
}

// init reads required templates located at templateRoot, parses them and adds them
// to a template map.
func (tf *TemplateFactory) init() {
	template_error_response := template.Must(template.ParseFiles(path.Join(tf.templateRoot, "error_response.html")))
	tf.templates["error_response"] = template_error_response
	template_approval_prompt := template.Must(template.ParseFiles(path.Join(tf.templateRoot, "approval_prompt.html")))
	tf.templates["approval_prompt"] = template_approval_prompt
	noTemplateFoundTemplate := template.Must(template.New("no_template_found").Parse("No template found"))
	tf.templates["no_template_found"] = noTemplateFoundTemplate
}

// NewTamplateFactory returns a new factory that reads templates from from templateRoot
// directory.
func NewTemplateFactory(templateRoot string) *TemplateFactory {
	tf := TemplateFactory{templateRoot, make(map[string]*template.Template), &sync.Mutex{}}
	tf.init()
	return &tf
}

// get returns a template matching the requested name. If the template id not found
// default template "no_template_found" is returned.
func (tf *TemplateFactory) get(name string) *template.Template {
	tf.mutex.Lock()
	defer tf.mutex.Unlock()
	if template, ok := tf.templates[name]; ok {
		return template
	}
	return tf.templates["no_template_found"]
}

// ExecuteTemplate applies template that has a given name to the specified data
// object and writes the output to writer w.
// A template may be executed safely in parallel.
// See html.template.ExecuteTemplate for more information.
func (tf *TemplateFactory) ExecuteTemplate(w io.Writer, name string, data interface{}) error {
	return tf.get(name).Execute(w, data)
}
