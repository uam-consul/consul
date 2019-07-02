(function() {
  "use strict";
  App.Globalize = {
    display_locale: function(locale) {
      App.Globalize.enable_locale(locale);
      $(".js-globalize-locale-link").each(function() {
        if ($(this).data("locale") === locale) {
          $(this).show();
          App.Globalize.highlight_locale($(this));
        }
        $(".js-globalize-locale option:selected").removeAttr("selected");
      });
    },
    display_translations: function(locale) {
      $(".js-globalize-attribute").each(function() {
        if ($(this).data("locale") === locale) {
          $(this).show();
        } else {
          $(this).hide();
        }
        $(".js-delete-language").hide();
        $("#js_delete_" + locale).show();
      });
    },
    highlight_locale: function(element) {
      $(".js-globalize-locale-link").removeClass("is-active");
      element.addClass("is-active");
    },
    remove_language: function(locale) {
      var next;
      $(".js-globalize-attribute[data-locale=" + locale + "]").each(function() {
        $(this).val("").hide();
        if (CKEDITOR.instances[$(this).attr("id")]) {
          CKEDITOR.instances[$(this).attr("id")].setData("");
        }
      });
      $(".js-globalize-locale-link[data-locale=" + locale + "]").hide();
      next = $(".js-globalize-locale-link:visible").first();
      App.Globalize.highlight_locale(next);
      App.Globalize.display_translations(next.data("locale"));
      App.Globalize.disable_locale(locale);
    },
    enable_locale: function(locale) {
      App.Globalize.destroy_locale_field(locale).val(false);
      App.Globalize.site_customization_enable_locale_field(locale).val(1);
    },
    disable_locale: function(locale) {
      App.Globalize.destroy_locale_field(locale).val(true);
      App.Globalize.site_customization_enable_locale_field(locale).val(0);
    },
    enabled_locales: function() {
      return $.map($(".js-globalize-locale-link:visible"), function(element) {
        return $(element).data("locale");
      });
    },
    destroy_locale_field: function(locale) {
      return $("input[id$=_destroy][data-locale=" + locale + "]");
    },
    site_customization_enable_locale_field: function(locale) {
      return $("#enabled_translations_" + locale);
    },
    refresh_visible_translations: function() {
      var locale;
      locale = $(".js-globalize-locale-link.is-active").data("locale");
      App.Globalize.display_translations(locale);
    },
    initialize: function() {
      $(".js-globalize-locale").on("change", function() {
        App.Globalize.display_translations($(this).val());
        App.Globalize.display_locale($(this).val());
      });
      $(".js-globalize-locale-link").on("click", function() {
        App.Globalize.display_translations($(this).data("locale"));
        App.Globalize.highlight_locale($(this));
      });
      $(".js-delete-language").on("click", function() {
        App.Globalize.remove_language($(this).data("locale"));
        $(this).hide();
      });
      $(".js-add-fields-container").on("cocoon:after-insert", function() {
        App.Globalize.enabled_locales().forEach(function(locale) {
          App.Globalize.enable_locale(locale);
        });
      });
    }
  };

}).call(this);
