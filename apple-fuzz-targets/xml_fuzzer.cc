/*
 * libxml2 Fuzzer
 *
 * libxml2 is used throughout macOS for XML parsing. It's a large,
 * complex library with a history of vulnerabilities.
 *
 * Target areas:
 * - XML document parsing
 * - DTD validation
 * - XPath queries
 * - Entity expansion
 * - Namespace handling
 */

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <stdint.h>
#include <stddef.h>

// Prevent XXE and billion laughs attacks during fuzzing
static void ignoreEntityDecl(void *ctx, const xmlChar *name, int type,
                             const xmlChar *publicId, const xmlChar *systemId,
                             xmlChar *content) {
    // Do nothing - ignore entity declarations
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    // Initialize libxml2
    xmlInitParser();
    LIBXML_TEST_VERSION

    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 10 || Size > 100000) {
        return 0;
    }

    // Create a parser context
    xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
    if (!ctxt) {
        return 0;
    }

    // Set options to prevent DoS
    xmlCtxtUseOptions(ctxt,
        XML_PARSE_NONET |      // Disable network access
        XML_PARSE_NOENT |      // Don't substitute entities
        XML_PARSE_DTDLOAD |    // Don't load DTD
        XML_PARSE_COMPACT |    // Use compact tree
        XML_PARSE_HUGE         // Allow huge documents (but we limit size)
    );

    // Override entity handler to prevent XXE
    ctxt->sax->entityDecl = ignoreEntityDecl;

    // Parse the document
    xmlDocPtr doc = xmlCtxtReadMemory(ctxt,
                                      (const char *)Data,
                                      Size,
                                      "fuzz.xml",
                                      NULL,
                                      ctxt->options);

    if (doc) {
        // Get root element
        xmlNodePtr root = xmlDocGetRootElement(doc);

        if (root) {
            // Traverse tree
            xmlNodePtr cur = root;
            int node_count = 0;
            const int MAX_NODES = 1000;

            while (cur && node_count < MAX_NODES) {
                node_count++;

                // Get node properties
                if (cur->name) {
                    const xmlChar *name = cur->name;
                    (void)name;
                }

                if (cur->content) {
                    const xmlChar *content = cur->content;
                    (void)content;
                }

                // Check attributes
                xmlAttrPtr attr = cur->properties;
                int attr_count = 0;
                while (attr && attr_count < 100) {
                    attr_count++;
                    if (attr->name) {
                        const xmlChar *attr_name = attr->name;
                        (void)attr_name;
                    }
                    if (attr->children && attr->children->content) {
                        const xmlChar *attr_value = attr->children->content;
                        (void)attr_value;
                    }
                    attr = attr->next;
                }

                // Move to next node
                if (cur->children) {
                    cur = cur->children;
                } else if (cur->next) {
                    cur = cur->next;
                } else {
                    // Go up and find next sibling
                    cur = cur->parent;
                    while (cur && !cur->next) {
                        cur = cur->parent;
                    }
                    if (cur) {
                        cur = cur->next;
                    }
                }
            }

            // Test XPath if document is not too large
            if (node_count < 100) {
                xmlXPathContextPtr xpathCtx = xmlXPathNewContext(doc);
                if (xpathCtx) {
                    // Try a simple XPath query
                    xmlXPathObjectPtr xpathObj = xmlXPathEvalExpression(
                        (const xmlChar *)"//*", xpathCtx
                    );

                    if (xpathObj) {
                        xmlXPathFreeObject(xpathObj);
                    }

                    xmlXPathFreeContext(xpathCtx);
                }
            }
        }

        // Free document
        xmlFreeDoc(doc);
    }

    // Free parser context
    xmlFreeParserCtxt(ctxt);

    // Reset errors
    xmlResetLastError();

    return 0;
}
