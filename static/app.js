

var ManagerCtrl = function ($scope, $http) {
	$scope.Posts = [];
	$scope.ClickPost = function (user, method) {
		$http({
			method: 'POST',
			url: '/click_post.html',
			params:{
				"user":user,
				"method":method
			}
		}).success(
			function(response, status, headers, config) {
				if (response.Code == 0) {
					alert("处理成功");
					document.location = response.Redirect
				}
				else {
					alert("处理失败:" + response.Code);
				}
			}
		).error(
			function(response, status, headers, config) {
				alert("服务器错误：" + status);
			}
		);
	}
};
