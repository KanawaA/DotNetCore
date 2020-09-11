var table = null;


$(document).ready(function () {
    //debugger;
    table = $('#department').DataTable({
        "processing": true,
        "responsive": true,
        "pegination": true,
        "stateSave": true,
        "ajax": {
            url: "/department/LoadDepart",
            type: "GET",
            dataType: "Json",
            dataSrc: "",
        },

        "columnDefs": [{
            sortable: false,
            "class": "index",
            targets: 0
        }],
        order: [[1, 'asc']],
        fixedColumns: true,

        "columns": [
            { "data": null },
            { "data": "name" },
            {
                "data": "createDate",
                'render': function (jsonDate) {
                    var date = new Date(jsonDate);
                    if (date.getFullYear() != 0001) {
                        return moment(date).format('DD MMMM YYYY')
                    }
                }
            },
            {
                "data": "updateDate",
                'render': function (jsonDate) {
                    var date = new Date(jsonDate);
                    if (date.getFullYear() != 0001) {
                        return moment(date).format('DD MMMM YYYY');
                    }
                    else {
                        return "Not Updated Yet"
                    }
                }
            },
            {
                "sortable": false,
                "data": "id",
                "render": function (data, type, row) {
                    console.log(row);
                    $('[data-toggle="tooltip"]').tooltip();
                    return '<button class="btn btn-link btn-md btn-warning " data-placement="left" data-toggle="tooltip" data-animation="false" title="Edit" onclick="return GetById(' + data + ')" ><i class="fa fa-lg fa-edit"></i></button>'
                        + '&nbsp;'
                        + '<button class="btn btn-link btn-md btn-danger" data-placement="right" data-toggle="tooltip" data-animation="false" title="Delete" onclick="return Delete(' + data + ')" ><i class="fa fa-lg fa-times"></i></button>'
                }
            },
        ]
    });
    table.on('order.dt search.dt', function () {
        table.column(0, { search: 'applied', order: 'applied' }).nodes().each(function (cell, i) {
            cell.innerHTML = i + 1;
        });
    }).draw();

});

function ClearScreen() {
    $('#Id').val('');
    $('#Name').val('');
    $('#update').hide();
    $('#add').show();
}

function GetById(id) {
    debugger;
    $.ajax({
        url: "/Department/GetById/",
        data: { id: id }
    }).then((result) => {
        //debugger;
        $('#Id').val(result.id);
        $('#Name').val(result.name);
        $('#add').hide();
        $('#update').show();
        $('#myModal').modal('show');
    })
}

function Save() {
    //debugger;
    var Dept = new Object();
    Dept.Id = 0;
    Dept.Name = $('#Name').val();
    $.ajax({
        type: 'POST',
        url: "/Department/InsertOrUpdate/",
        cache: false,
        dataType: "JSON",
        data: Dept
    }).then((result) => {
        if (result.statusCode === 200) {
            Swal.fire({
                position: 'center',
                icon: 'success',
                title: 'Data inserted Successfully',
                showConfirmButton: false,
                timer: 1500,
            })
            table.ajax.reload(null, false);
        } else {
            Swal.fire('Error', 'Failed to Input', 'error');
            ClearScreen();
        }
    })
}

function Update() {
    debugger;
    var Dept = new Object();
    Dept.Id = $('#Id').val();
    Dept.Name = $('#Name').val();
    $.ajax({
        type: 'POST',
        url: "/Department/InsertOrUpdate/",
        cache: false,
        dataType: "JSON",
        data: Dept
    }).then((result) => {
        //debugger;
        if (result.statusCode === 200) {
            Swal.fire({
                position: 'center',
                icon: 'success',
                title: 'Data Updated Successfully',
                showConfirmButton: false,
                timer: 1500,
            });
            table.ajax.reload(null, false);
        } else {
            Swal.fire('Error', 'Failed to Input', 'error');
            ClearScreen();
        }
    })
}

function Delete(id) {
    debugger
    Swal.fire({
        title: 'Are you sure?',
        text: "You won't be able to revert this!",
        showCancelButton: true,
        confirmButtonColor: '#3085d6',
        cancelButtonColor: '#d33',
        confirmButtonText: 'Yes, delete it!',
    }).then((result) => {
        if (result.value) {
            debugger;
            $.ajax({
                url: "/Department/Delete/",
                data: { id: id }
            }).then((result) => {
                debugger;
                if (result.statusCode === 200) {
                    debugger;
                    Swal.fire({
                        position: 'center',
                        icon: 'success',
                        title: 'Delete Successfully',
                        showConfirmButton: false,
                        timer: 1500,
                    });
                    table.ajax.reload(null, false);
                } else {
                    Swal.fire('Error', 'Failed to Delete', 'error');
                    ClearScreen();
                }
            })
        };
    });
}