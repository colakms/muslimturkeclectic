/**
 * Created by Sinansas on 6/30/2014.
 */

$(document).ready(function() {
   var error_message = $('<h2 style="font-size: 14px; color: black;">You have to enter a name and a comment.</h2>');
    $('#comment_form').hide();
    $('#comment_wrapper').hide();
    $('#newcomment').on('click', function() {
         $(this).closest('.templatemo_post').find('#comment_form').slideToggle();
        event.preventDefault();
        event.stopPropagation();
    });
    $('#comments').on('click', function() {
        var hr = $("<hr class=\"line\">")
        var comment_wrapper = $(this).closest('.templatemo_post').find('#comment_wrapper');
        if(comment_wrapper.is(":hidden")) comment_wrapper.prepend(hr).slideDown();
        else {
            comment_wrapper.hide()
            comment_wrapper.find('.line').remove();
        }
        event.preventDefault();
        event.stopPropagation();
    });
    $('#comment_button').on('click', function(event) {
        if($('#comment_inputfield').val() === "" && $('#comment_content').val() === "") {
            $(this).closest("#comment_form").append(error_message);
            event.preventDefault();
            event.stopPropagation();
        }
    });
});