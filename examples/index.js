
function on_see_also(see_also)
{
        if ( is_expanded() )
        {
                // likely it is, since I clicked on "see also";
                // close it

                expand_toggle(name_expanded);
        }

        expand_toggle(see_also);

        document.getElementById('IMG_' + see_also).scrollIntoView();
        return true;
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
