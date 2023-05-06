
function on_see_also(see_also)
{
        var idx = see_also.indexOf("#");
        if ( idx > -1 )
                see_also = see_also.substring(idx+1,see_also.length);
        var entry = find_entry_el(document.getElementById('DIV_' + see_also));
        if ( entry )
        {
                set_entry_state(entry, true);
                entry.scrollIntoView();
        }
}

function find_parent_with_class(el, klass)
{
        while ( el )
        {
                if ( el.className && el.className.indexOf(klass) > -1 )
                        return el;
                el = el.parentNode;
        }
}

function find_child_with_class(el, klass)
{
        return el.querySelector("." + klass);
}

function find_entry_el(el) { return find_parent_with_class(el, "example-entry"); }
function find_expander(entry_el) { return find_child_with_class(entry_el, "expander"); }
function find_collapser(entry_el) { return find_child_with_class(entry_el, "collapser"); }

function set_entry_state(entry_el, expanded)
{
        var collapser_el = find_collapser(entry_el);
        var expander_el = find_expander(entry_el);
        collapser_el.style.display = expanded ? "" : "none";
        expander_el.style.display = expanded ? "none" : "";
        if ( expanded )
                entry_el.classList.remove("collapsed-entry");
        else
                entry_el.classList.add("collapsed-entry");
}

function handle_click(e)
{
        e = e || window.event;
        var el = e.target || e.srcElement;
        var entry_el = find_entry_el(el);
        var ok = false;
        if ( el.classList.contains("collapser") )
                set_entry_state(entry_el, false);
        else if ( el.classList.contains("expander") )
                set_entry_state(entry_el, true);
        else if ( el.classList.contains("ex_link") ) // see also
                on_see_also(el.href);
        else
                return;
        e.stopPropagation();
}

function handle_toplevel_action(e)
{
        e = e || window.event;
        var el = e.target || e.srcElement;
        var expanded = el.classList.contains("expand-all");
        var els = document.getElementsByClassName("example-entry");
        for ( var idx = 0, n = els.length; idx < n; ++idx )
                set_entry_state(els[idx], expanded);
        e.stopPropagation();
}
