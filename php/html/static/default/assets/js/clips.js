$(".recent-activity .ok").live("click",
function(e) {
  $(this).tooltip("hide");
  $(this).parents("li").fadeOut(500,
  function() {
    return $(this).remove();
  });
  return e.preventDefault();
});
$(".recent-activity .remove").live("click",
function(e) {
  $(this).tooltip("hide");
  $(this).parents("li").fadeOut(500,
  function() {
    return $(this).remove();
  });
  return e.preventDefault();
});
$("#comments-more-activity").live("click",
function(e) {
  $(this).button("loading");
  setTimeout((function() {
    var list;
    list = $("#comments-more-activity").parent().parent().find("ul");
    list.append(list.find("li:not(:first)").clone().effect("highlight", {},
    500));
    return $("#comments-more-activity").button("reset");
  }), 1000);
  e.preventDefault();
  return false;
});
$("#users-more-activity").live("click",
function(e) {
  $(this).button("loading");
  setTimeout((function() {
    var list;
    list = $("#users-more-activity").parent().parent().find("ul");
    list.append(list.find("li:not(:first)").clone().effect("highlight", {},
    500));
    return $("#users-more-activity").button("reset");
  }), 1000);
  e.preventDefault();
  return false;
});

$("input.nakedpassword").nakedPassword({
  path: "assets/images/plugins/naked_password/"
});

var select2icon;
select2icon = function(e) {
  return "<i class='" + e.text + "'></i> ." + e.text;
};
$("#select2-icon").select2({
  formatResult: select2icon,
  formatSelection: select2icon,
  escapeMarkup: function(e) {
    return e;
  }
});
$("#select2-tags").select2({
  tags: ["today", "tomorrow", "toyota"],
  tokenSeparators: [",", " "],
  placeholder: "Type your tag here... "
});

$("#daterange2").daterangepicker({
  format: "MM/DD/YYYY"
},
function(start, end) {
  return $("#daterange2").parent().find("input").first().val(start.format("MMMM D, YYYY") + " - " + end.format("MMMM D, YYYY"));
});

$(".mention").mention({
  users: [{
    name: "Lindsay Made",
    username: "LindsayM",
    image: "http://placekitten.com/25/25"
  },
  {
    name: "Rob Dyrdek",
    username: "robdyrdek",
    image: "http://placekitten.com/25/24"
  },
  {
    name: "Rick Bahner",
    username: "RickyBahner",
    image: "http://placekitten.com/25/23"
  },
  {
    name: "Jacob Kelley",
    username: "jakiestfu",
    image: "http://placekitten.com/25/22"
  },
  {
    name: "John Doe",
    username: "HackMurphy",
    image: "http://placekitten.com/25/21"
  },
  {
    name: "Charlie Edmiston",
    username: "charlie",
    image: "http://placekitten.com/25/20"
  },
  {
    name: "Andrea Montoya",
    username: "andream",
    image: "http://placekitten.com/24/20"
  },
  {
    name: "Jenna Talbert",
    username: "calisunshine",
    image: "http://placekitten.com/23/20"
  },
  {
    name: "Street League",
    username: "streetleague",
    image: "http://placekitten.com/22/20"
  },
  {
    name: "Loud Mouth Burrito",
    username: "Loudmouthfoods",
    image: "http://placekitten.com/21/20"
  }]
});

$.validator.addMethod("buga", (function(value) {
  return value === "buga";
}), "Please enter \"buga\"!");

$.validator.methods.equal = function(value, element, param) {
  return value === param;
};

$("#alert-example").live("click",
function(e) {
  bootbox.alert({
    message: "I am alert!",
  });
  return false;
});

$("#notification1").live("click",
function(e) {
  $.jGrowl("Lorem ipsum dolor sit amet...");
  return false;
});

$("#notification2").live("click",
function(e) {
  $.jGrowl("Lorem ipsum dolor sit amet...", {
    sticky: true
  });
  return false;
});

var date, months, timeago;
selector = $("#timeago-example");
date = new Date();
months = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
timeago = selector;
timeago.attr("title", "" + months[date.getMonth()] + " " + (date.getDate()) + ", " + (date.getFullYear()) + " " + (date.getHours()) + ":" + (date.getMinutes()));
timeago.text("" + months[date.getMonth()] + " " + (date.getDate()) + ", " + (date.getFullYear()) + " " + (date.getHours()) + ":" + (date.getMinutes()));
timeago.timeago();

$("#slider-example > span").each(function() {
  var value;
  value = parseInt($(this).text(), 10);
  return $(this).empty().slider({
    value: value,
    range: "min",
    animate: true,
    orientation: "vertical"
  });
});

$("#slider-example1").slider({
  value: 100,
  min: 0,
  max: 500,
  step: 50,
  slide: function(event, ui) {
    return $("#slider-example1-amount").text("$" + ui.value);
  }
});

$("#slider-example1-amount").text("$" + $("#slider-example1").slider("value"));

$("#slider-example2").slider({
  range: true,
  min: 0,
  max: 500,
  values: [75, 300],
  slide: function(event, ui) {
    return $("#slider-example2-amount").text("$" + ui.values[0] + " - $" + ui.values[1]);
  }
});

$("#slider-example2-amount").text("$" + $("#slider-example2").slider("values", 0) + " - $" + $("#slider-example2").slider("values", 1));

(function() {
  $("#tree1").dynatree();

  $("#tree2").dynatree({
    checkbox: true,
    selectMode: 2,
    onSelect: function(select, node) {
      var selKeys, selNodes;
      selNodes = node.tree.getSelectedNodes();
      selKeys = $.map(selNodes,
      function(node) {
        return "[" + node.data.key + "]: '" + node.data.title + "'";
      });
      return $("#echoSelection2").text(selKeys.join(", "));
    },
    onClick: function(node, event) {
      if (node.getEventTargetType(event) === "title") {
        return node.toggleSelect();
      }
    },
    onKeydown: function(node, event) {
      if (event.which === 32) {
        node.toggleSelect();
        return false;
      }
    },
    idPrefix: "dynatree-Cb2-"
  });

  $("#tree3").dynatree({
    dnd: {
      preventVoidMoves: true,
      onDragStart: function(node) {
        return true;
      },
      onDragEnter: function(node, sourceNode) {
        return ["before", "after"];
      },
      onDrop: function(node, sourceNode, hitMode, ui, draggable) {
        return sourceNode.move(node, hitMode);
      }
    }
  });

}).call(this);

$(".todo-list .new-todo").live('submit',
function(e) {
  var li, todo_name;
  todo_name = $(this).find("#todo_name").val();
  $(this).find("#todo_name").val("");
  if (todo_name.length !== 0) {
    li = $(this).parents(".todo-list").find("li.item").first().clone();
    li.find("input[type='checkbox']").attr("checked", false);
    li.removeClass("important").removeClass("done");
    li.find("label.todo span").text(todo_name);
    $(".todo-list ul").first().prepend(li);
    li.effect("highlight", {},
    500);
  }
  return e.preventDefault();
});

$(".todo-list .actions .remove").live("click",
function(e) {
  $(this).tooltip("hide");
  $(this).parents("li").fadeOut(500,
  function() {
    return $(this).remove();
  });
  e.stopPropagation();
  e.preventDefault();
  return false;
});

$(".todo-list .actions .important").live("click",
function(e) {
  $(this).parents("li").toggleClass("important");
  e.stopPropagation();
  e.preventDefault();
  return false;
});

$(".todo-list .check").live("click",
function() {
  var checkbox;
  checkbox = $(this).find("input[type='checkbox']");
  if (checkbox.is(":checked")) {
    return $(this).parents("li").addClass("done");
  } else {
    return $(this).parents("li").removeClass("done");
  }
});